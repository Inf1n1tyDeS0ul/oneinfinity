# Scan-Filtered Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the findings count in Scan History clickable so it switches to the Findings tab showing only that scan's findings.

**Architecture:** Add `scan_id` to the findings API response (backend one-liner), then wire up in-page state in `Results.jsx` so clicking a scan's findings count sets a `scanFilter` and switches tabs; `FindingsTab` filters the global store by `scan_id` and shows a dismissable banner.

**Tech Stack:** FastAPI (Python), React 18, Zustand, React Router, Tailwind

---

## File Map

| File | Change |
|---|---|
| `web/backend/main.py` | Add `scan_id` field to `_finding_to_api` return dict |
| `web/frontend/src/pages/Results.jsx` | Wire `scanFilter` state; clickable findings count; filter + banner in `FindingsTab` |
| `tests/test_finding_to_api.py` | New — tests that `_finding_to_api` includes `scan_id` |

---

### Task 1: Backend — expose `scan_id` in findings API response

**Files:**
- Modify: `web/backend/main.py` (~line 453, `_finding_to_api` function)
- Create: `tests/test_finding_to_api.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_finding_to_api.py`:

```python
# tests/test_finding_to_api.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from web.backend.main import _finding_to_api


def test_finding_to_api_includes_scan_id():
    """_finding_to_api must pass scan_id through to the API dict."""
    raw = {
        "finding_id": "abc123",
        "title": "SQL Injection",
        "severity": "high",
        "target": "example.com",
        "scan_id": "gm-be922d",
    }
    result = _finding_to_api(raw)
    assert result["scan_id"] == "gm-be922d"


def test_finding_to_api_scan_id_defaults_to_empty_string():
    """_finding_to_api must return scan_id='' when the raw finding has none."""
    raw = {"finding_id": "xyz", "title": "XSS", "severity": "medium", "target": "t.com"}
    result = _finding_to_api(raw)
    assert result["scan_id"] == ""
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_finding_to_api.py -v
```

Expected: 2 FAILs — `KeyError: 'scan_id'` or `AssertionError`.

- [ ] **Step 3: Add `scan_id` to `_finding_to_api`**

In `web/backend/main.py`, find `_finding_to_api` (around line 453). The function returns a dict — add one line after `"created_at"`:

```python
def _finding_to_api(f) -> dict:
    """Convert NormalizedFinding dataclass or dict to API dict."""
    if hasattr(f, '__dict__'):
        f = f.__dict__
    return {
        "id": f.get("finding_id", f.get("id", str(uuid.uuid4())[:8])),
        "target": f.get("target", ""),
        "title": f.get("title", ""),
        "severity": f.get("severity", "info"),
        "attack_type": f.get("vuln_type", f.get("attack_type", "")),
        "tool": f.get("tool", ""),
        "evidence": f.get("evidence", ""),
        "payload": f.get("payload", ""),
        "url": f.get("url", ""),
        "confidence": f.get("confidence", 0.8),
        "cvss": f.get("cvss", 0.0),
        "status": f.get("status", "new"),
        "source_type": f.get("source_type", "tool"),
        "created_at": f.get("created_at", datetime.utcnow().isoformat()),
        "scan_id": f.get("scan_id", ""),
        "bounty_score": f.get("bounty_score", 0.0),
        "estimated_payout": f.get("estimated_payout", ""),
        "priority_rank": f.get("priority_rank", 0),
        "reproduction_steps": "",
        "tags": [],
        "remediation": "",
        "response": "",
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_finding_to_api.py -v
```

Expected: 2 PASSes.

- [ ] **Step 5: Commit**

```bash
git add tests/test_finding_to_api.py web/backend/main.py
git commit -m "feat(api): expose scan_id in findings API response"
```

---

### Task 2: Frontend — wire scan filter state in Results

**Files:**
- Modify: `web/frontend/src/pages/Results.jsx` (the `Results` default export, bottom of file)

This task only adds the `scanFilter` state to `Results` and threads the props down. The tab components are updated in Tasks 3 and 4. No visible behaviour changes yet.

- [ ] **Step 1: Update the `Results` component**

Replace the `Results` default export (currently lines 425–467) with:

```jsx
export default function Results() {
  const [tab, setTab] = useState('findings')
  const [scanFilter, setScanFilter] = useState(null) // { id, target } | null

  const handleViewFindings = (scan) => {
    setScanFilter({ id: scan.id, target: scan.target })
    setTab('findings')
  }

  const handleClearFilter = () => setScanFilter(null)

  return (
    <div className="flex flex-col gap-4">
      {/* Page header + tabs */}
      <div className="flex items-center gap-4">
        <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <ShieldAlert size={15} className="text-red-400" />
          Results
        </h1>
        <div className="flex items-center gap-1 bg-bg-secondary border border-bg-border rounded p-0.5">
          <button
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors',
              tab === 'findings'
                ? 'bg-accent-primary/20 text-accent-primary'
                : 'text-slate-400 hover:text-slate-200'
            )}
            onClick={() => setTab('findings')}
          >
            <ShieldAlert size={11} />
            Findings
          </button>
          <button
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors',
              tab === 'history'
                ? 'bg-accent-primary/20 text-accent-primary'
                : 'text-slate-400 hover:text-slate-200'
            )}
            onClick={() => setTab('history')}
          >
            <History size={11} />
            Scan History
          </button>
        </div>
      </div>

      {tab === 'findings'
        ? <FindingsTab scanFilter={scanFilter} onClearFilter={handleClearFilter} />
        : <ScanHistoryTab onViewFindings={handleViewFindings} />
      }
    </div>
  )
}
```

- [ ] **Step 2: Verify the app still renders**

```bash
cd /path/to/oneinfinity/web/frontend
npm run build 2>&1 | tail -20
```

Expected: build succeeds (warnings about unused props are fine at this stage).

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/pages/Results.jsx
git commit -m "feat(results): add scanFilter state and prop threading"
```

---

### Task 3: Frontend — clickable findings count in ScanHistoryTab

**Files:**
- Modify: `web/frontend/src/pages/Results.jsx` (`ScanHistoryTab` component)

- [ ] **Step 1: Update `ScanHistoryTab` signature and findings cell**

`ScanHistoryTab` currently has signature `function ScanHistoryTab()`. Change it to accept `onViewFindings` and update the findings count cell.

Change the function signature:

```jsx
function ScanHistoryTab({ onViewFindings }) {
```

Find the findings count cell (currently renders `{s.findings_count ?? s.findings ?? 0}`). Replace that `<td>` with:

```jsx
<td className="px-3 py-2.5 text-slate-400">
  {(s.findings_count ?? s.findings ?? 0) > 0 ? (
    <button
      className="text-accent-primary hover:underline tabular-nums"
      onClick={e => { e.stopPropagation(); onViewFindings(s) }}
    >
      {s.findings_count ?? s.findings}
    </button>
  ) : (
    <span>0</span>
  )}
</td>
```

- [ ] **Step 2: Build and verify no errors**

```bash
cd /path/to/oneinfinity/web/frontend
npm run build 2>&1 | tail -20
```

Expected: clean build.

- [ ] **Step 3: Manual smoke test**

Start the dev server (`npm run dev` or however the project runs — check `package.json` scripts). Navigate to Results → Scan History. Verify:
- Scans with 0 findings show plain "0"
- Scans with findings show a highlighted/underline number
- Clicking the number switches to the Findings tab (filter not active yet — that's Task 4)

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/pages/Results.jsx
git commit -m "feat(results): make findings count clickable in scan history"
```

---

### Task 4: Frontend — filter and banner in FindingsTab

**Files:**
- Modify: `web/frontend/src/pages/Results.jsx` (`FindingsTab` component)
- Add import: `X` from `lucide-react`

- [ ] **Step 1: Add `X` to the lucide-react import**

At the top of `Results.jsx`, find the lucide import line:

```jsx
import {
  ShieldAlert, History, Search, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, StopCircle, RefreshCw, Trash2
} from 'lucide-react'
```

Add `X` to the list:

```jsx
import {
  ShieldAlert, History, Search, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, StopCircle, RefreshCw, Trash2, X
} from 'lucide-react'
```

- [ ] **Step 2: Update `FindingsTab` signature and add scan pre-filter**

Change the function signature from `function FindingsTab()` to:

```jsx
function FindingsTab({ scanFilter, onClearFilter }) {
```

Currently the component has:

```jsx
const filtered = vulnerabilities.filter(v => {
  if (sevFilter && v.severity !== sevFilter) return false
  if (statusFilter && v.status !== statusFilter) return false
  if (search) {
    const q = search.toLowerCase()
    if (
      !v.title?.toLowerCase().includes(q) &&
      !v.target?.toLowerCase().includes(q) &&
      !v.tool?.toLowerCase().includes(q)
    ) return false
  }
  return true
})

const total = vulnerabilities.length
const critical = vulnerabilities.filter(v => v.severity === 'critical').length
const high = vulnerabilities.filter(v => v.severity === 'high').length
const confirmed = vulnerabilities.filter(v => v.status === 'confirmed').length
```

Replace it with:

```jsx
// When a scan filter is active, scope to that scan first
const scoped = scanFilter
  ? vulnerabilities.filter(v => v.scan_id === scanFilter.id)
  : vulnerabilities

const filtered = scoped.filter(v => {
  if (sevFilter && v.severity !== sevFilter) return false
  if (statusFilter && v.status !== statusFilter) return false
  if (search) {
    const q = search.toLowerCase()
    if (
      !v.title?.toLowerCase().includes(q) &&
      !v.target?.toLowerCase().includes(q) &&
      !v.tool?.toLowerCase().includes(q)
    ) return false
  }
  return true
})

const total = scoped.length
const critical = scoped.filter(v => v.severity === 'critical').length
const high = scoped.filter(v => v.severity === 'high').length
const confirmed = scoped.filter(v => v.status === 'confirmed').length
```

- [ ] **Step 3: Add the context banner to the JSX**

In the `FindingsTab` return, find the opening `<div className="flex flex-col gap-4">`. Add the banner as the first child, before the stats cards:

```jsx
return (
  <div className="flex flex-col gap-4">
    {/* Scan context banner — shown when filtered to a specific scan */}
    {scanFilter && (
      <div className="flex items-center gap-2 px-3 py-2 rounded bg-accent-primary/10 border border-accent-primary/20 text-xs">
        <ShieldAlert size={11} className="text-accent-primary flex-shrink-0" />
        <span className="text-slate-300">
          Findings for <span className="text-slate-100 font-medium">{scanFilter.target}</span>
          <span className="text-slate-500 ml-1">({scanFilter.id})</span>
        </span>
        <button
          className="ml-auto flex items-center gap-1 text-slate-400 hover:text-slate-200 transition-colors"
          onClick={onClearFilter}
        >
          <X size={11} />
          All Scans
        </button>
      </div>
    )}

    {/* Stats cards */}
    ...rest of existing JSX unchanged...
```

- [ ] **Step 4: Build to verify no errors**

```bash
cd /path/to/oneinfinity/web/frontend
npm run build 2>&1 | tail -20
```

Expected: clean build, no TypeScript/JSX errors.

- [ ] **Step 5: Manual end-to-end test**

With the dev server running:

1. Navigate to **Results → Scan History**
2. Find a completed scan with findings count > 0 (e.g. "32")
3. Click the findings count number
4. Verify: switches to **Findings** tab, banner shows "Findings for www.vulnbank.org (gm-be922d)", stats cards show counts for that scan only, table shows only that scan's findings
5. Click **× All Scans** in the banner
6. Verify: banner disappears, all findings shown again, stats cards reflect full set
7. Switching to **Scan History** tab and back to **Findings** tab — filter should persist until cleared

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/pages/Results.jsx
git commit -m "feat(results): filter findings by scan with dismissable banner"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| `scan_id` added to `_finding_to_api` | Task 1 |
| Findings count clickable when > 0 | Task 3 |
| Clicking switches to Findings tab | Task 2 (`handleViewFindings`) |
| Findings tab filters by `scan_id` | Task 4 step 2 |
| Stats cards reflect filtered subset | Task 4 step 2 (`scoped` variable) |
| Dismissable "× All Scans" banner | Task 4 step 3 |
| No new API endpoints or store changes | Confirmed — only `_finding_to_api` + JSX |

**Placeholder scan:** None found.

**Type consistency:** `scanFilter` is `{ id, target }` throughout. `onViewFindings(scan)` passes the full scan object from the store; `handleViewFindings` extracts `.id` and `.target`. `onClearFilter` sets `scanFilter` to `null`. All consistent.
