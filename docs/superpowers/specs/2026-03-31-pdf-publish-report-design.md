# PDF Publish Report — Design Spec

**Date:** 2026-03-31  
**Status:** Approved  
**Feature:** Publish Report tab with professional PDF generation and in-app preview

---

## Overview

Add a "Publish Report" tab to the Reports page. The user selects a scan, chooses which sections to include, and clicks "Publish Report". The app navigates to a full-screen routable overlay (`/report-preview/:scanId`) that renders the generated PDF in an iframe with a Download button.

---

## Architecture & Data Flow

```
Reports page
  └── "Publish Report" tab
        ├── Scan selector dropdown  ← GET /api/scans
        ├── Section checkboxes (all checked by default)
        └── [Publish Report] button
              │
              ▼
        navigate to /report-preview/:scanId?sections=exec,findings,chains,meta,remediation
              │
              ▼
        ReportPreview page (full-screen routable overlay)
              ├── POST /api/reports/publish  { scan_id, sections[] }
              │     └── backend: Reporter.write("pdf") → streams PDF bytes
              ├── <iframe src={blobURL}>  — renders the PDF in-browser
              └── [Download PDF] button → a.download trigger
```

### Backend endpoint

**`POST /api/reports/publish`**

- Request body: `{ "scan_id": "<id>", "sections": ["exec", "findings", "chains", "meta", "remediation"] }`
- Calls existing `core/reporter.py` `Reporter` class with a `sections` filter param
- Returns: `application/pdf` binary stream
- Error: `400` if scan not found, `500` on generation failure

### Frontend routing

New route added to React Router:

```
/report-preview/:scanId   →   ReportPreview.jsx
```

The overlay is full-viewport fixed-position (z-50), giving the routable-modal UX: accessible via direct URL and navigable back with the close button.

---

## Report Content & Sections

All sections are individually togglable via checkboxes. Default: all checked.

| Key | Section | Content |
|-----|---------|---------|
| `exec` | Cover Page + Executive Summary | OneInfinity logo, report title, target URL, scan date; risk score, findings by severity, scan duration, phases run |
| `findings` | Findings Detail | Per-finding: title, severity, CVSS, description, evidence, affected endpoint, remediation |
| `chains` | Attack Chains | Exploit chains as text (A→B→C), CVSS uplift |
| `meta` | Scan Metadata | Target, scan ID, phases completed, tools run, timestamps |
| `remediation` | Remediation Summary | Deduplicated remediation actions grouped by priority |

### Branding

- **Header** (every page): OneInfinity logo (left) + "OneInfinity Security Report" text (right), background `#0f172a`
- **Footer** (every page): Page numbers centered, generation timestamp right-aligned
- **Severity colors**: Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray — matching the web UI palette
- **Font**: Helvetica (built into fpdf2, no font embedding needed)

---

## Frontend Components

### `Reports.jsx` — new "Publish Report" tab

- Tab label: "Publish Report" (with `FileDown` Lucide icon to match existing tab style)
- **Scan selector**: dropdown populated from existing scans API; shows scan ID + target + date
- **Section checklist**: 6 checkboxes, all checked by default, labeled clearly
- **Publish Report button**: disabled until a scan is selected; on click navigates to `/report-preview/:scanId?sections=<csv>`

### `ReportPreview.jsx` — new page component

- **Layout**: fixed full-viewport overlay (z-50, bg-gray-950), no app nav chrome
- **Close button**: top-right `×`, navigates back (`useNavigate(-1)`)
- **On mount**: reads `scanId` from route params and `sections` from query string → `POST /api/reports/publish` → receives blob → `URL.createObjectURL` → sets as `<iframe src>`
- **Loading state**: centered spinner with "Generating report…" text
- **Error state**: inline error message + "Retry" button
- **Download button**: top-right (next to close), `<a href={blobURL} download="oneinfinity-report-{scanId}.pdf">` with `Download` Lucide icon; disabled while loading
- **Cleanup**: `URL.revokeObjectURL` on component unmount

---

## Backend Implementation Notes

### `core/reporter.py` changes

- Add `sections: list[str] | None = None` parameter to `Reporter.__init__` (or `write()`)
- When `sections` is provided, skip generation of any section whose key is not in the list
- Cover page is always included (not independently togglable — it's part of `exec`)

### `web/backend/main.py` changes

- Add `POST /api/reports/publish` endpoint
- Fetch scan data from the scan store by `scan_id`
- Instantiate `Reporter(scan_data, sections=sections)`
- Write PDF to a `BytesIO` buffer
- Return `StreamingResponse(buffer, media_type="application/pdf")`

---

## File Changes Summary

| File | Change |
|------|--------|
| `core/reporter.py` | Add `sections` filter param; add cover page, branding header/footer, all 5 section renderers |
| `web/backend/main.py` | Add `POST /api/reports/publish` endpoint |
| `web/frontend/src/pages/Reports.jsx` | Add "Publish Report" tab with scan selector + section checklist |
| `web/frontend/src/pages/ReportPreview.jsx` | New component — full-screen PDF preview overlay |
| `web/frontend/src/App.jsx` (or router file) | Add `/report-preview/:scanId` route |

---

## Out of Scope

- Logo upload or custom branding (always OneInfinity branded)
- Email delivery of reports
- Saving published reports to disk server-side (PDF is generated on demand)
- HTML preview mode (iframe of PDF blob is the preview)
