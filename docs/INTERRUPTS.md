# Graceful Shutdown & Interrupt Handling

**OneInfinity CLI Interrupt Behavior**  
Last Updated: 2026-05-26

---

## Overview

As of Phase 5 fix (May 2026), CLI scans support graceful shutdown. Pressing Ctrl+C no longer loses findings.

---

## Behavior

### Before Fix (v1.0.0)

```
User: python cli_scan.py example.com
Scanner: [Collects 50 findings over 5 minutes]
User: [Presses Ctrl+C]
CLI: "Scan interrupted by user"
→ Exit code 130
→ Findings LOST (not saved to database)
```

### After Fix (v1.0.1+)

```
User: python cli_scan.py example.com
Scanner: [Collects 50 findings over 5 minutes]
User: [Presses Ctrl+C]
CLI: "Interrupt received - stopping gracefully..."
CLI: "Collected findings will be saved to database"
Scanner: [Saves 50 findings to DB]
CLI: "Scan stopped. Partial results saved: 50 findings"
→ Exit code 130
→ Findings SAVED
```

---

## Technical Details

### Signal Handlers

**Registered Signals:**
- `SIGINT` (Ctrl+C)
- `SIGTERM` (kill command)

**Handler Logic:**

```python
def signal_handler(signum, frame):
    if active_scan_id:
        # Signal scanner to stop
        get_engine().stop(active_scan_id)
        # Scanner checks stop_event after each phase
        # Saves collected findings before exit
    sys.exit(130)
```

### Scanner Stop Mechanism

**How It Works:**

1. CLI generates unique scan ID
2. Registers signal handler before scan starts
3. On interrupt, calls `engine.stop(scan_id)`
4. Scanner checks `stop_event` after each phase
5. If set, saves findings and returns partial results
6. CLI exits gracefully

**Phase Checkpoints:**

Scanner checks for stop signal after:
- Recon phase
- Vulnerability scan phase
- Validation phase
- Chain detection phase
- Report generation phase

**Minimum Save Interval:** After each phase completion (~30-60 seconds)

---

## Usage

### Normal Scan

```bash
python cli_scan.py https://example.com
# Let it complete normally
```

### Interrupted Scan

```bash
python cli_scan.py https://example.com
# Wait for some findings...
# Press Ctrl+C

# Output:
[*] Interrupt received - stopping gracefully...
[*] Collected findings will be saved to database
[*] Scan stopped. Partial results saved: 42 findings
```

### Force Quit

```bash
python cli_scan.py https://example.com
# Press Ctrl+C once → graceful stop
# Press Ctrl+C again → force quit (may lose findings)
```

**Warning:** Double Ctrl+C bypasses graceful shutdown and may lose data.

---

## Verification

### Check Findings Saved

```bash
# After interrupted scan
sqlite3 ~/.oneinfinity/databases/findings.db "SELECT COUNT(*) FROM findings WHERE scan_id = '<scan_id>';"
```

### Check Scan Status

```bash
# Interrupted scans marked as 'interrupted' or 'partial'
sqlite3 ~/.oneinfinity/databases/findings.db "SELECT scan_id, status FROM scans ORDER BY created_at DESC LIMIT 5;"
```

---

## Edge Cases

### Mid-Phase Interrupt

**Scenario:** Ctrl+C pressed during long-running nuclei scan

**Behavior:**
- Current phase continues until completion
- Findings from completed phase saved
- Subsequent phases skipped

**Worst Case:** Up to 1 phase worth of findings may be incomplete

### Multiple Scans

**Scenario:** Multiple CLI scans running in parallel

**Behavior:**
- Each scan has unique ID
- Interrupt only affects scan in current terminal
- Other scans continue unaffected

### Background Scans (UI)

**Scenario:** Scan triggered from web UI

**Behavior:**
- UI has separate cancel mechanism
- Not affected by CLI signal handlers
- Graceful cancellation via API endpoint

---

## Comparison to Other Tools

| Tool | Interrupt Behavior | Data Loss |
|------|-------------------|-----------|
| Nuclei | Immediate exit | Yes (all findings) |
| SQLMap | Immediate exit | Yes (current test) |
| Burp | Pause option | No (auto-save) |
| OneInfinity v1.0.0 | Immediate exit | Yes (all findings) |
| **OneInfinity v1.0.1+** | **Graceful stop** | **No (saves before exit)** |

---

## Troubleshooting

### Findings Still Lost

**Check:**
1. Version: `oneinfinity --version` (must be 1.0.1+)
2. Database writable: `touch ~/.oneinfinity/databases/test && rm ~/.oneinfinity/databases/test`
3. PostgreSQL reachable: `psql $POSTGRES_URL -c "SELECT 1;"`

### Scan Won't Stop

**Symptoms:** Ctrl+C does nothing

**Causes:**
- Blocking subprocess (nuclei/sqlmap hung)
- Signal handler not registered

**Solution:**
- Press Ctrl+C twice (force quit)
- Report issue with reproduction steps

### Double Ctrl+C Required

**Expected Behavior:** First Ctrl+C = graceful, second = force

**If First Press Does Nothing:**
- Bug - report with logs

---

## Implementation Details

**Files Changed:**
- `cli_scan.py` (40 lines added)
  - Signal handler registration
  - Scan ID tracking
  - Engine stop invocation

**Scanner Changes:**
- None required (stop mechanism already existed)
- CLI now properly invokes it

**Backward Compatibility:**
- Old code continues to work
- New behavior opt-in (only in CLI)
- API scans unaffected

---

## Best Practices

### When to Interrupt

**Good Reasons:**
- Testing scanner functionality
- Target appears down/unresponsive
- Accidentally scanned wrong target
- Found critical vuln, want to report immediately

**Bad Reasons:**
- Scan taking too long (use `--quick` mode instead)
- Too many findings (they're deduped, let it complete)

### After Interrupting

1. Check findings count
2. Review what was scanned
3. Consider resuming if incomplete
4. Generate report from partial results

---

## Future Enhancements

**Planned:**
- [ ] Resume from checkpoint
- [ ] Progress persistence
- [ ] Partial report generation
- [ ] Better phase granularity

**Not Planned:**
- Real-time finding save (too much DB overhead)
- Sub-phase interrupts (too complex)

---

## References

- [PHASE4_5_COMBINED_FIX_EVIDENCE.md](../PHASE4_5_COMBINED_FIX_EVIDENCE.md)
- [REMEDIATION_COMPLETE_SUMMARY.md](../REMEDIATION_COMPLETE_SUMMARY.md)

---

**Questions?** Open GitHub issue with `interrupt-handling` label
