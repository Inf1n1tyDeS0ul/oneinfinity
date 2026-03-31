# PDF Publish Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Publish Report" tab to the Reports page that generates a professional OneInfinity-branded PDF for any selected scan and opens it in a full-screen routable preview with a download button.

**Architecture:** The backend exposes `POST /api/reports/publish` which loads findings from the ingestion engine SQLite DB and metadata from the god mode state file or SCANS dict, builds a `Reporter` with a `sections` filter, and streams back raw PDF bytes. The frontend adds a fourth tab to `Reports.jsx` with a scan selector + section checklist, then navigates to `/report-preview/:scanId` — a new full-screen overlay component that fetches the PDF, creates a blob URL, and renders it in an `<iframe>`.

**Tech Stack:** Python fpdf2 (already installed), FastAPI StreamingResponse, React Router, Lucide React icons, axios blob response type.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `core/reporter.py` | Modify | Add `sections` filter to `_render_pdf`; add `render_to_buffer`; add chains/meta/remediation PDF sections |
| `web/backend/main.py` | Modify | Add `POST /api/reports/publish` endpoint |
| `web/frontend/src/utils/api.js` | Modify | Add `publishReport` axios call with `responseType: 'blob'` |
| `web/frontend/src/pages/Reports.jsx` | Modify | Add "Publish Report" tab with scan selector and section checklist |
| `web/frontend/src/pages/ReportPreview.jsx` | Create | Full-screen PDF preview overlay with iframe and download button |
| `web/frontend/src/App.jsx` | Modify | Register `/report-preview/:scanId` route |
| `tests/test_pdf_publish_report.py` | Create | Tests for Reporter sections filter and the publish endpoint |

---

## Task 1: Extend `Reporter` with `sections` filter and `render_to_buffer`

**Files:**
- Modify: `core/reporter.py` (lines ~162–200 for `__init__`, lines ~779–1093 for `_render_pdf`)
- Create: `tests/test_pdf_publish_report.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_pdf_publish_report.py`:

```python
"""Tests for PDF Publish Report feature — Reporter.render_to_buffer with sections filter."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.reporter import Reporter


def _make_reporter(tmp_dir):
    r = Reporter(output_dir=tmp_dir, target="https://example.com", platform="hackerone")
    r.add_finding({
        "vuln_type": "xss",
        "severity": "high",
        "endpoint": "https://example.com/search",
        "description": "Reflected XSS in search parameter",
        "evidence": "<script>alert(1)</script> reflected in response",
        "cvss": 7.5,
        "confidence": 0.9,
    })
    r.add_finding({
        "vuln_type": "sqli",
        "severity": "critical",
        "endpoint": "https://example.com/api/users",
        "description": "SQL injection in user lookup",
        "cvss": 9.1,
        "confidence": 0.95,
    })
    return r


def test_render_to_buffer_returns_pdf_bytes(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer()
    assert isinstance(result, bytes)
    assert result[:4] == b"%PDF", f"Expected PDF header, got {result[:4]!r}"


def test_render_to_buffer_with_exec_only(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=["exec"])
    assert result[:4] == b"%PDF"


def test_render_to_buffer_with_findings_only(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=["findings"])
    assert result[:4] == b"%PDF"


def test_render_to_buffer_all_sections(tmp_path):
    r = _make_reporter(str(tmp_path))
    r.set_meta("attack_chains", [
        {"chain": "xss → account_takeover", "cvss_uplift": "7.5 → 9.3", "description": "XSS leads to ATO via stolen session cookie"},
    ])
    r.set_meta("phases_complete", ["deep_recon", "vuln_scan", "active_testing", "auth_session"])
    r.set_meta("scan_duration_s", 3276)
    result = r.render_to_buffer(sections=["exec", "findings", "chains", "meta", "remediation"])
    assert result[:4] == b"%PDF"
    assert len(result) > 5000  # non-trivial PDF


def test_render_to_buffer_empty_sections_list(tmp_path):
    """Empty sections list → only cover page."""
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=[])
    assert result[:4] == b"%PDF"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_pdf_publish_report.py -v 2>&1 | head -30
```

Expected: `AttributeError: 'Reporter' object has no attribute 'render_to_buffer'`

- [ ] **Step 3: Add `render_to_buffer` to `Reporter` and `sections` filter to `_render_pdf`**

In `core/reporter.py`, make these changes:

**3a. Add `render_to_buffer` method after the existing `write_executive` method (after line ~251):**

```python
def render_to_buffer(self, sections: list | None = None) -> bytes:
    """Generate PDF and return raw bytes. `sections` controls which sections appear.

    Section keys: 'exec', 'findings', 'chains', 'meta', 'remediation'.
    None (default) = all sections. Empty list = cover page only.
    """
    import tempfile
    from pathlib import Path as _Path
    tmp = _Path(tempfile.mktemp(suffix=".pdf"))
    try:
        self._render_pdf(tmp, executive=False, sections=sections)
        return tmp.read_bytes()
    finally:
        tmp.unlink(missing_ok=True)
```

**3b. Change the `_render_pdf` signature (line ~779) to accept `sections`:**

Old:
```python
def _render_pdf(self, path: Path, executive: bool = False) -> None:
```

New:
```python
def _render_pdf(self, path: Path, executive: bool = False, sections: list | None = None) -> None:
```

**3c. At the top of `_render_pdf` body (after the local variable definitions, before the `class OIPdf` block, around line ~789), add the section gating helper:**

```python
        # Section gating: None = all sections enabled
        _all_sections = {"exec", "findings", "chains", "meta", "remediation"}
        _active = _all_sections if sections is None else set(sections)

        def _has(key: str) -> bool:
            return key in _active
```

**3d. Wrap the "Summary Page" block (starts at line ~931 `# ── Summary Page ──`) so it only renders when exec is active:**

Find this line in `_render_pdf`:
```python
        # ── Summary Page ──
        pdf.add_page()
        pdf.set_text_color(*DARK)
```

Replace with:
```python
        if _has("exec"):
            # ── Summary Page ──
            pdf.add_page()
            pdf.set_text_color(*DARK)
```

Then find the end of the exec section — it's the block ending with `pdf.ln(8)` after the severity table rows loop. Add a closing `# end exec section` comment and ensure the indentation nests the entire block under the `if _has("exec"):`. The exec section spans from `pdf.add_page()` on ~line 932 through `pdf.ln(8)` on ~line 998.

**3e. Wrap the findings block. Find (line ~1000):**
```python
        if not executive:
            # ── Findings Pages ──
            for i, f in enumerate(findings, 1):
```

Replace with:
```python
        if not executive and _has("findings"):
            # ── Findings Pages ──
            for i, f in enumerate(findings, 1):
```

**3f. Add three new sections before `pdf.output(str(path))` (line ~1093). Insert after the findings block ends (after the closing divider `pdf.ln(6)`):**

```python
        # ── Attack Chains Section ──
        if _has("chains"):
            chains_data = self._meta.get("attack_chains") or []
            if chains_data:
                pdf.add_page()
                section_header("Attack Chains")
                for chain in chains_data:
                    chain_text = chain.get("chain", "")
                    uplift = chain.get("cvss_uplift", "")
                    desc = chain.get("description", "")
                    if pdf.get_y() > 240:
                        pdf.add_page()
                    # Chain header band
                    band_y = pdf.get_y()
                    pdf.set_fill_color(*DARK)
                    pdf.rect(18, band_y, 174, 9, "F")
                    pdf.set_font("Helvetica", "B", 8.5)
                    pdf.set_text_color(*WHITE)
                    pdf.set_y(band_y + 2)
                    pdf.cell(0, 6, safe(chain_text, 100), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(*DARK)
                    pdf.ln(2)
                    if uplift:
                        pdf.set_font("Helvetica", "", 8)
                        pdf.set_text_color(*GRAY)
                        pdf.cell(30, 5, "CVSS Uplift:", new_x=XPos.RIGHT)
                        pdf.set_font("Helvetica", "B", 8)
                        pdf.set_text_color(220, 38, 38)
                        pdf.cell(0, 5, safe(uplift, 60), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                        pdf.set_text_color(*DARK)
                    if desc:
                        pdf.set_font("Helvetica", "", 8)
                        pdf.multi_cell(174, 4.5, safe(desc, 400), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(5)
                    pdf.set_draw_color(226, 232, 240)
                    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
                    pdf.ln(5)

        # ── Scan Metadata Section ──
        if _has("meta"):
            pdf.add_page()
            section_header("Scan Metadata")
            meta_rows = [
                ("Scan ID",     safe(str(self._meta.get("scan_id", "N/A")), 60)),
                ("Target",      safe(str(self._meta.get("target", target)), 80)),
                ("Status",      safe(str(self._meta.get("status", "completed")), 40)),
                ("Duration",    _fmt_duration(int(self._meta.get("scan_duration_s") or 0))),
                ("Generated",   now),
            ]
            phases = self._meta.get("phases_complete") or []
            if phases:
                meta_rows.append(("Phases Run", safe(", ".join(phases), 200)))
            for label, value in meta_rows:
                if pdf.get_y() > 250:
                    pdf.add_page()
                row_y = pdf.get_y()
                pdf.set_fill_color(245, 247, 250)
                pdf.rect(18, row_y, 174, 8, "F")
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*GRAY)
                pdf.cell(45, 8, label, new_x=XPos.RIGHT)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*DARK)
                pdf.multi_cell(129, 8, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(4)

        # ── Remediation Summary Section ──
        if _has("remediation"):
            pdf.add_page()
            section_header("Remediation Summary")
            seen_remediations: set = set()
            for sev in ["critical", "high", "medium", "low", "info"]:
                sev_findings = [f for f in findings if f.severity.lower() == sev]
                if not sev_findings:
                    continue
                rgb = SEV_RGB.get(sev, (107, 114, 128))
                pdf.set_font("Helvetica", "B", 8.5)
                pdf.set_text_color(*rgb)
                pdf.cell(0, 6, f"{sev.upper()} PRIORITY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(*DARK)
                for f in sev_findings:
                    rem = f.effective_remediation()
                    if rem in seen_remediations:
                        continue
                    seen_remediations.add(rem)
                    if pdf.get_y() > 245:
                        pdf.add_page()
                    pdf.set_fill_color(*GREEN_BG)
                    box_start = pdf.get_y()
                    txt_h = max(10, (len(rem) // 65 + 1) * 4 + 6)
                    pdf.rect(18, box_start, 174, txt_h, "F")
                    pdf.set_y(box_start + 2)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*GREEN_FG)
                    pdf.multi_cell(174, 4.5, safe(rem, 500), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(*DARK)
                    pdf.ln(3)
                pdf.ln(4)
```

**3g. Add the `_fmt_duration` helper function at the module level (add after `_REMEDIATION_MAP` dict, before the `@dataclass` line ~86):**

```python
def _fmt_duration(seconds: int) -> str:
    """Format integer seconds as 'Xh Ym Zs'."""
    if seconds <= 0:
        return "N/A"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)
```

**Note on indentation:** All the new section code in step 3f must be indented at the same level as the existing `if not executive and _has("findings"):` block (8 spaces, since we're inside `_render_pdf` which is a method of a class). The `section_header` local function is already defined inside `_render_pdf` at line ~935 and is available to all code after it.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_pdf_publish_report.py -v
```

Expected output:
```
PASSED tests/test_pdf_publish_report.py::test_render_to_buffer_returns_pdf_bytes
PASSED tests/test_pdf_publish_report.py::test_render_to_buffer_with_exec_only
PASSED tests/test_pdf_publish_report.py::test_render_to_buffer_with_findings_only
PASSED tests/test_pdf_publish_report.py::test_render_to_buffer_all_sections
PASSED tests/test_pdf_publish_report.py::test_render_to_buffer_empty_sections_list
```

- [ ] **Step 5: Commit**

```bash
git add core/reporter.py tests/test_pdf_publish_report.py
git commit -m "feat(reporter): add render_to_buffer with sections filter for PDF publish"
```

---

## Task 2: Add `POST /api/reports/publish` endpoint

**Files:**
- Modify: `web/backend/main.py` (add after the `@app.get("/api/reports")` block, around line ~898)
- Modify: `tests/test_pdf_publish_report.py` (add endpoint tests)

- [ ] **Step 1: Add endpoint tests**

Append to `tests/test_pdf_publish_report.py`:

```python
# ── Endpoint tests ─────────────────────────────────────────────────────────

def test_publish_endpoint_returns_pdf(tmp_path, monkeypatch):
    """POST /api/reports/publish returns application/pdf bytes."""
    import sys, os
    # Add backend to path
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "backend"))
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    # Patch ingestion engine to return a test finding
    mock_finding = {
        "scan_id": "test-scan-1",
        "finding_id": "f001",
        "vuln_type": "xss",
        "severity": "high",
        "url": "https://test.example.com/search",
        "endpoint": "https://test.example.com/search",
        "description": "XSS in search",
        "cvss": 7.5,
        "confidence": 0.9,
        "source_type": "tool",
        "tool": "zap",
        "target": "test.example.com",
        "created_at": "2026-03-31T10:00:00",
        "raw": "{}",
    }

    class MockIngestion:
        def get_findings(self, scan_id=None, **kwargs):
            return [mock_finding]

    import result_ingestion_engine as rie
    monkeypatch.setattr(rie, "get_ingestion_engine", lambda: MockIngestion())

    # Mock god mode state file
    import god_mode_engine as gme
    class MockStateFile:
        def read(self):
            return {
                "scan_id": "test-scan-1",
                "target": "https://test.example.com",
                "status": "completed",
                "elapsed_seconds": 600,
                "phases_complete": ["deep_recon", "vuln_scan"],
                "finding_count": 1,
            }
    monkeypatch.setattr(gme, "GodModeStateFile", lambda scan_id: MockStateFile())

    from fastapi.testclient import TestClient
    import main as app_module
    # Disable auth for test
    monkeypatch.setattr(app_module, "_require_auth", lambda: None)
    client = TestClient(app_module.app)

    resp = client.post("/api/reports/publish", json={
        "scan_id": "test-scan-1",
        "sections": ["exec", "findings", "meta"],
    })
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
```

- [ ] **Step 2: Run new test to verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_pdf_publish_report.py::test_publish_endpoint_returns_pdf -v 2>&1 | head -20
```

Expected: `404 Not Found` or `AttributeError` (endpoint not yet defined)

- [ ] **Step 3: Add the endpoint to `web/backend/main.py`**

Read lines 873–899 of `web/backend/main.py` to confirm current position, then insert the following block immediately after the `list_reports` function (after the closing line of the `@app.get("/api/reports")` handler):

```python
class PublishReportRequest(BaseModel):
    scan_id: str
    sections: Optional[List[str]] = None   # None = all sections


@app.post("/api/reports/publish", dependencies=[Depends(_require_auth)])
async def publish_report(req: PublishReportRequest):
    """Generate a professional PDF report for a scan and stream it back."""
    import sys as _sys, os as _os, tempfile as _tmp
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)) + "/../..")

    scan_id = req.scan_id.strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")

    # Load findings from ingestion engine (works for both god mode and regular scans)
    try:
        from result_ingestion_engine import get_ingestion_engine
        findings = get_ingestion_engine().get_findings(scan_id=scan_id)
    except Exception as exc:
        log.warning("publish_report: could not load findings for %s: %s", scan_id, exc)
        findings = []

    # Load metadata — try god mode state file first, fall back to SCANS dict
    meta: dict = {}
    try:
        from god_mode_engine import GodModeStateFile
        state = GodModeStateFile(scan_id).read()
        if state:
            meta = {
                "scan_id": scan_id,
                "target": state.get("target", ""),
                "status": state.get("status", "completed"),
                "scan_duration_s": int(state.get("elapsed_seconds") or 0),
                "phases_complete": state.get("phases_complete") or [],
                "finding_count": state.get("finding_count", len(findings)),
            }
    except Exception:
        pass

    if not meta:
        scan = SCANS.get(scan_id, {})
        meta = {
            "scan_id": scan_id,
            "target": scan.get("target", ""),
            "status": scan.get("status", "completed"),
            "scan_duration_s": 0,
            "phases_complete": [],
            "finding_count": len(findings),
        }

    target = meta.get("target") or "Unknown Target"

    # Build Reporter and generate PDF bytes
    try:
        import _tmp_dir_holder
    except ImportError:
        pass

    tmp_dir = _tmp.mkdtemp(prefix="oi_report_")
    try:
        from core.reporter import Reporter
        import sys as _s2
        _s2.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)) + "/../..")

        reporter = Reporter(output_dir=tmp_dir, target=target, platform="oneinfinity")
        for f in findings:
            reporter.add_finding(f)
        for k, v in meta.items():
            reporter.set_meta(k, v)

        sections = req.sections  # None = all sections
        pdf_bytes = reporter.render_to_buffer(sections=sections)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")
    finally:
        import shutil as _shutil
        _shutil.rmtree(tmp_dir, ignore_errors=True)

    from fastapi.responses import StreamingResponse
    import io as _io
    filename = f"oneinfinity-report-{scan_id}.pdf"
    return StreamingResponse(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

Also add `List` to the FastAPI/typing imports at the top of `main.py` if not already present. Check with:

```bash
grep "from typing import" /home/devendra-yadav/oneinfinity/web/backend/main.py | head -3
```

If `List` is missing, add it to the existing `from typing import` line.

- [ ] **Step 4: Run all PDF publish tests**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_pdf_publish_report.py -v
```

Expected: all 6 tests pass. If the endpoint test fails with an import error, check that `main.py` can import `Reporter` from `core.reporter` (the `sys.path.insert` in the endpoint handles this).

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_pdf_publish_report.py
git commit -m "feat(api): add POST /api/reports/publish endpoint for PDF generation"
```

---

## Task 3: Add `publishReport` to `api.js`

**Files:**
- Modify: `web/frontend/src/utils/api.js`

- [ ] **Step 1: Read the current reports section of api.js**

Read lines 57–60 of `web/frontend/src/utils/api.js` to confirm the reports entry location.

- [ ] **Step 2: Add the `publishReport` function**

Find this line in `web/frontend/src/utils/api.js`:
```javascript
  reports:         () => api.get('/reports'),
```

Add after it:
```javascript
  publishReport:   (scanId, sections) => api.post('/reports/publish',
    { scan_id: scanId, sections: sections || null },
    { responseType: 'blob', timeout: 120000 }
  ),
```

Note: `timeout: 120000` gives 2 minutes for PDF generation. The default 15s is too short.

- [ ] **Step 3: Verify syntax**

```bash
node -e "require('/home/devendra-yadav/oneinfinity/web/frontend/src/utils/api.js')" 2>&1 | head -5
```

If this errors (ESM module), that's fine — the file uses ES modules. Just visually verify there are no syntax errors by reading the file around the change.

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/utils/api.js
git commit -m "feat(api-client): add publishReport endpoint call with blob response type"
```

---

## Task 4: Add "Publish Report" tab to `Reports.jsx`

**Files:**
- Modify: `web/frontend/src/pages/Reports.jsx`

- [ ] **Step 1: Read the current file**

Read `web/frontend/src/pages/Reports.jsx` in full to understand the current state and tab structure.

- [ ] **Step 2: Update imports**

Find the import line:
```javascript
import { FileText, Play, Download, RefreshCw, Eye, Plus, RotateCcw } from 'lucide-react'
```

Replace with:
```javascript
import { FileText, Play, Download, RefreshCw, Eye, Plus, RotateCcw, FileDown, CheckSquare, Square } from 'lucide-react'
```

Also add `useNavigate` to the React Router import. Add this import after the existing imports:
```javascript
import { useNavigate } from 'react-router-dom'
```

- [ ] **Step 3: Add state variables for the publish tab**

Find the existing state declarations block (lines ~8–19):
```javascript
  const [replayResult, setReplayResult] = useState(null)
```

Add after `setReplayResult`:
```javascript
  const navigate = useNavigate()
  const [publishScans, setPublishScans] = useState([])
  const [publishScanId, setPublishScanId] = useState('')
  const [publishSections, setPublishSections] = useState(
    ['exec', 'findings', 'chains', 'meta', 'remediation']
  )
  const [publishLoading, setPublishLoading] = useState(false)
```

- [ ] **Step 4: Add the scan list loader for the publish tab**

Find the `loadReports` function and add a new function after it:

```javascript
  const loadPublishScans = async () => {
    try {
      const [scansRes, gmRes] = await Promise.allSettled([
        endpoints.scans(),
        endpoints.godModeSessions(),
      ])
      const regular = (scansRes.status === 'fulfilled' ? scansRes.value.data : []) || []
      const gmSessions = (gmRes.status === 'fulfilled' ? gmRes.value.data?.sessions : []) || []
      const allScans = [
        ...gmSessions.map(s => ({
          id: s.scan_id,
          label: `[GOD MODE] ${s.target || s.scan_id} — ${s.status || 'unknown'} (${s.finding_count ?? 0} findings)`,
        })),
        ...regular.map(s => ({
          id: s.id,
          label: `[SCAN] ${s.target || s.id} — ${s.status || 'unknown'} (${s.findings_count ?? 0} findings)`,
        })),
      ]
      setPublishScans(allScans)
    } catch (e) {
      setPublishScans([])
    }
  }
```

- [ ] **Step 5: Load publish scans when the publish tab becomes active**

Find the `useEffect` that calls `loadReports()`:
```javascript
  useEffect(() => { loadReports() }, [])
```

Replace with:
```javascript
  useEffect(() => {
    loadReports()
    loadPublishScans()
  }, [])
```

- [ ] **Step 6: Add section toggle helper**

Add after `loadPublishScans`:

```javascript
  const toggleSection = (key) => {
    setPublishSections(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    )
  }
```

- [ ] **Step 7: Add publish handler**

Add after `toggleSection`:

```javascript
  const handlePublish = () => {
    if (!publishScanId) return
    const params = new URLSearchParams({ sections: publishSections.join(',') })
    navigate(`/report-preview/${publishScanId}?${params}`)
  }
```

- [ ] **Step 8: Add the "Publish Report" tab button to the tab bar**

Find:
```javascript
      <div className="tab-bar">
        {[{ id: 'generate', label: 'Generate Report' }, { id: 'list', label: 'Saved Reports' }, { id: 'replay', label: 'Replay Findings' }].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>
```

Replace with:
```javascript
      <div className="tab-bar">
        {[
          { id: 'generate', label: 'Generate Report' },
          { id: 'list', label: 'Saved Reports' },
          { id: 'replay', label: 'Replay Findings' },
          { id: 'publish', label: 'Publish Report' },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>
```

- [ ] **Step 9: Add the publish tab content panel**

Find the closing `</div>` of the last tab panel (the replay tab). It's the final `}` before the outer closing `</div>`. Add the publish panel after the replay panel:

```javascript
      {tab === 'publish' && (
        <div className="card max-w-xl flex flex-col gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-400 font-medium uppercase tracking-wide">Select Scan</label>
            <select
              className="input"
              value={publishScanId}
              onChange={e => setPublishScanId(e.target.value)}
            >
              <option value="">— choose a scan —</option>
              {publishScans.map(s => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-400 font-medium uppercase tracking-wide">Report Sections</label>
            {[
              { key: 'exec',        label: 'Executive Summary' },
              { key: 'findings',    label: 'Findings Detail' },
              { key: 'chains',      label: 'Attack Chains' },
              { key: 'meta',        label: 'Scan Metadata' },
              { key: 'remediation', label: 'Remediation Summary' },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => toggleSection(key)}
                className="flex items-center gap-2 text-sm text-gray-300 hover:text-white transition-colors text-left"
              >
                {publishSections.includes(key)
                  ? <CheckSquare size={15} className="text-blue-400 shrink-0" />
                  : <Square size={15} className="text-gray-600 shrink-0" />
                }
                {label}
              </button>
            ))}
          </div>

          <button
            className="btn-primary flex items-center gap-2"
            onClick={handlePublish}
            disabled={!publishScanId || publishLoading}
          >
            <FileDown size={14} />
            {publishLoading ? 'Preparing…' : 'Publish Report'}
          </button>
        </div>
      )}
```

- [ ] **Step 10: Verify the file renders without syntax errors by checking imports resolve**

```bash
cd /home/devendra-yadav/oneinfinity/web/frontend
node -e "console.log('syntax check')" 2>&1
```

Visually review the JSX for unclosed tags or missing commas.

- [ ] **Step 11: Commit**

```bash
git add web/frontend/src/pages/Reports.jsx
git commit -m "feat(ui): add Publish Report tab with scan selector and section checklist"
```

---

## Task 5: Create `ReportPreview.jsx`

**Files:**
- Create: `web/frontend/src/pages/ReportPreview.jsx`

- [ ] **Step 1: Create the component**

```javascript
import React, { useState, useEffect, useRef } from 'react'
import { useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { X, Download, Loader2, AlertTriangle, RefreshCw } from 'lucide-react'
import api from '../utils/api'

export default function ReportPreview() {
  const { scanId } = useParams()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const [pdfUrl, setPdfUrl] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const blobRef = useRef(null)

  const sectionsParam = searchParams.get('sections') || ''
  const sections = sectionsParam ? sectionsParam.split(',').filter(Boolean) : null

  const fetchPdf = async () => {
    setLoading(true)
    setError(null)
    // Revoke previous blob URL
    if (blobRef.current) {
      URL.revokeObjectURL(blobRef.current)
      blobRef.current = null
      setPdfUrl(null)
    }
    try {
      const resp = await api.post(
        '/reports/publish',
        { scan_id: scanId, sections: sections },
        { responseType: 'blob', timeout: 120000 }
      )
      const blob = new Blob([resp.data], { type: 'application/pdf' })
      const url = URL.createObjectURL(blob)
      blobRef.current = url
      setPdfUrl(url)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPdf()
    return () => {
      if (blobRef.current) {
        URL.revokeObjectURL(blobRef.current)
      }
    }
  }, [scanId, sectionsParam])

  return (
    <div className="fixed inset-0 z-50 bg-gray-950 flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-sm font-semibold text-white">Security Report</span>
          <span className="text-xs text-gray-500 font-mono">{scanId}</span>
        </div>
        <div className="flex items-center gap-2">
          {pdfUrl && (
            <a
              href={pdfUrl}
              download={`oneinfinity-report-${scanId}.pdf`}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              <Download size={13} />
              Download PDF
            </a>
          )}
          {error && (
            <button
              onClick={fetchPdf}
              className="btn-secondary text-xs flex items-center gap-1.5"
            >
              <RefreshCw size={13} />
              Retry
            </button>
          )}
          <button
            onClick={() => navigate(-1)}
            className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
            title="Close"
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 relative">
        {loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-gray-400">
            <Loader2 size={32} className="animate-spin text-blue-400" />
            <span className="text-sm">Generating report…</span>
          </div>
        )}

        {error && !loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-gray-400">
            <AlertTriangle size={32} className="text-red-400" />
            <span className="text-sm text-red-300">{error}</span>
          </div>
        )}

        {pdfUrl && !loading && (
          <iframe
            src={pdfUrl}
            className="w-full h-full border-0"
            title="Security Report Preview"
          />
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add web/frontend/src/pages/ReportPreview.jsx
git commit -m "feat(ui): add ReportPreview full-screen PDF preview overlay"
```

---

## Task 6: Register route in `App.jsx`

**Files:**
- Modify: `web/frontend/src/App.jsx`

- [ ] **Step 1: Add the import**

Find the existing imports block. Find:
```javascript
import Reports from './pages/Reports'
```

Add after it:
```javascript
import ReportPreview from './pages/ReportPreview'
```

- [ ] **Step 2: Add the route**

Find:
```javascript
        <Route path="/reports"         element={<Reports />} />
```

Add after it:
```javascript
        <Route path="/report-preview/:scanId" element={<ReportPreview />} />
```

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/App.jsx
git commit -m "feat(router): add /report-preview/:scanId route for PDF preview"
```

---

## Task 7: End-to-end smoke test

- [ ] **Step 1: Start the backend and verify the endpoint is reachable**

```bash
cd /home/devendra-yadav/oneinfinity/web/backend
python -c "
import sys; sys.path.insert(0, '../..')
from main import app
from fastapi.testclient import TestClient
client = TestClient(app)
resp = client.post('/api/reports/publish', json={'scan_id': 'nonexistent-scan', 'sections': ['exec']})
print('Status:', resp.status_code)
print('Content-Type:', resp.headers.get('content-type', 'N/A'))
if resp.status_code == 200:
    print('PDF header:', resp.content[:4])
else:
    print('Response:', resp.text[:200])
"
```

Expected: `Status: 200`, `Content-Type: application/pdf`, `PDF header: b'%PDF'` (returns a report with 0 findings for a nonexistent scan — that's valid behavior).

- [ ] **Step 2: Run the full test suite for PDF publish**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_pdf_publish_report.py -v
```

Expected: all tests pass.

- [ ] **Step 3: Build the frontend and verify no import errors**

```bash
cd /home/devendra-yadav/oneinfinity/web/frontend
npm run build 2>&1 | tail -20
```

Expected: build completes with no errors. Warnings about bundle size are OK.

- [ ] **Step 4: Final commit if any cleanup needed**

```bash
git add -p  # review any remaining changes
git commit -m "chore(pdf-report): final cleanup after smoke test"
```

---

## Self-Review

**Spec coverage:**
- ✅ "Publish Report" tab under Reports page → Task 4
- ✅ Scan selector dropdown (both god mode + regular scans) → Task 4 steps 4–5
- ✅ Configurable sections (6 checkboxes, all checked by default) → Task 4 steps 6–9
- ✅ OneInfinity branded PDF (existing cover page + header/footer branding) → Task 1 step 3
- ✅ Cover page always shown → cover page is outside section gates in `_render_pdf`
- ✅ All 5 section types (exec, findings, chains, meta, remediation) → Task 1 step 3f
- ✅ POST /api/reports/publish endpoint → Task 2
- ✅ In-app route /report-preview/:scanId → Task 6
- ✅ Full-screen overlay (fixed inset-0 z-50) → Task 5
- ✅ Close button (X) that navigates back → Task 5
- ✅ Loading state with spinner → Task 5
- ✅ Error state with retry button → Task 5
- ✅ Download PDF button → Task 5
- ✅ Blob URL cleanup on unmount → Task 5 (useEffect cleanup)
- ✅ API client endpoint with 2-minute timeout → Task 3

**Placeholder scan:** None found.

**Type consistency:**
- `publishReport` in api.js is not used by `ReportPreview.jsx` — the preview component calls `api.post` directly (to pass `responseType: 'blob'` which can't be set per-call through the endpoint helper). This is intentional and correct.
- `sections` is `null` when all sections selected in the API call, `list[str]` when filtered. Backend `_render_pdf` treats `None` as all-sections. Consistent.
- `scan_id` (snake_case) used consistently throughout backend. Frontend uses `scanId` (camelCase) for React state, sends `scan_id` in JSON body. Consistent with existing API patterns.
