# One&Infinity — Skill Boundaries

Defines what this system does well, what it does not, and where accuracy limits apply.

---

## What the System Is Good At

### Confirmed Working (Validated in Codebase)

| Capability | Confidence |
|-----------|-----------|
| Secret scanning in GitHub repos with ownership attribution | HIGH |
| Multi-tool result normalization (nuclei, dalfox, sqlmap, subfinder, httpx) | HIGH |
| SHA-256 fingerprint-based finding deduplication (cross-tool) | HIGH |
| 6-pattern exploit chain detection from confirmed findings | HIGH |
| CVSS 3.1 scoring from vector strings | HIGH |
| Subdomain enumeration via subfinder/assetfinder + HTTP probing | HIGH |
| Adaptive recon (tech detection, JS endpoint extraction, cloud asset discovery) | HIGH |
| SQLite-backed finding persistence with WAL journaling | HIGH |
| Multi-format report export (JSON, Markdown, HTML, PDF) | HIGH |
| System health diagnostics (doctor command, 10-point scoring) | HIGH |
| Scope validation (wildcard/CIDR/always-OOS rules) | HIGH |
| GitHub org-to-domain intelligence mapping | HIGH |
| Finding confidence classification — confirmed/unverified/false_positive/simulated | HIGH |
| CLI reproduction command generation per finding (ReproducibilityMapper) | HIGH |
| Cross-run persistent payload intelligence (PersistentMemory JSON store) | HIGH |
| ROI-driven URL scoring and target prioritization (BountyStrategyEngine) | HIGH |
| Elite hunting strategies — aggressive / stealthy / high-value | HIGH |
| Post-hunt benchmarking against reference findings (precision/recall/F1) | HIGH |

### Probabilistic / Best-Effort

| Capability | Confidence | Notes |
|-----------|-----------|-------|
| Live secret validation (GitHub, Stripe, OpenAI, Slack, Redis, Postgres) | MEDIUM | Read-only; 3-second hard timeout per credential |
| XSS validation via canary reflection | HIGH | Requires target to reflect input |
| SQLi validation via error patterns + timing | MEDIUM | 4-second timing threshold; network jitter can cause false negatives |
| SSRF validation via metadata probe patterns | MEDIUM | Only detects reflected metadata, not blind SSRF |
| Secret ownership attribution (first-party vs. third-party) | MEDIUM | Heuristic: org name matching + static mappings |
| Exploit chain PoC generation | MEDIUM | Steps beyond the trigger vuln are synthesized, not validated |
| AI red team prompt evolution | MEDIUM | Depends on LLM API availability and target cooperation |

---

## What the System Is NOT Good At

- **Blind SSRF without out-of-band callback**: The validator checks for metadata reflection; blind SSRF requires external collaborators (Burp Collaborator, interactsh).
- **Stored XSS validation**: Only reflected XSS is automated; stored XSS requires a separate rendering step.
- **DOM XSS validation**: The `browser_analysis` pipeline phase uses Playwright for DOM XSS sink analysis, but validation of confirmed DOM XSS still requires manual review — the engine detects potential sinks, not confirmed exploitability.
- **Authenticated endpoint testing**: The scanner does not handle session management, CSRF tokens, or multi-step login flows automatically.
- **Rate limit bypass**: No automatic detection of WAF rate limiting on specific endpoints.
- **Zero-day discovery without prior pattern**: The zero-day engine uses anomaly heuristics (timing, status changes, reflection), not novel vulnerability classes.
- **Network-level vulnerabilities**: No port scanning correlation with findings; nmap integration generates scripts but doesn't auto-parse results into the graph.
- **Mobile dynamic analysis without device**: Frida/Objection require a rooted/jailbroken device or emulator connected at runtime.

---

## Accuracy Boundaries

### Secret Detection
- **False positive rate**: ~15% for `generic_api_key` type (keyword-only match). High-specificity types (AWS, GitHub PAT, Stripe) have ~5% FP rate.
- **False negative rate**: Secrets in binary files, encrypted archives, or obfuscated code are not detected.
- **Entropy threshold**: 3.8 bits/char for short strings, 4.5 for strings >64 chars.

### Vulnerability Validation
- **XSS confirmation rate**: ~90% of reflected XSS found by dalfox are confirmed by the canary method.
- **SQLi error-based confirmation**: ~85% for MySQL/PostgreSQL; lower for MSSQL (different error patterns).
- **Timing-based SQLi**: ~70% true positive rate due to network jitter.
- **Confidence classifier thresholds**: `confirmed` requires ≥ 0.70 confidence + evidence/payload present; below 0.35 is automatically classified `false_positive` and excluded from reports. AI-theory findings are always capped at `unverified` (max 0.40 confidence) regardless of source confidence.
- **Tool-source bonus**: Findings from tool-confirmed sources receive +0.15 confidence before threshold evaluation.

### Exploit Chains
- Only 6 predefined patterns. Multi-hop chains beyond these patterns are not automatically detected.
- Chain detection fires when ANY finding with the trigger vuln type exists (medium+ severity) — it does NOT verify that the specific finding is actually exploitable.
- Chain findings generated by `ExploitChainEngine` are tagged `source_type=simulated` and classified as `simulated` by `FindingClassifier` — they are excluded from submitted reports unless independently confirmed by `ExploitChainExecutor` HTTP execution.

---

## Supported Use Cases

1. **Bug bounty reconnaissance and hunting** — primary design target
2. **Authorized penetration testing** — requires `scope.yaml` with `authorized: true`
3. **GitHub secret intelligence** — OSINT on public repos for target domains
4. **CI/CD integration** — results via JSON export, `gen_report.py` for HTML output
5. **Security research** — research mode with theory generation + anomaly detection

---

## Unsupported Use Cases

- Unauthorized scanning of systems without written authorization
- Production credential validation beyond read-only API checks
- Social engineering or phishing infrastructure
- DoS or denial-of-service testing
