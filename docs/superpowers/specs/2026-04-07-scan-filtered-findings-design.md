# Spec: Scan-Filtered Findings

**Date:** 2026-04-07
**Status:** Approved

## Problem

The Results page Findings tab shows all findings from all scans globally. When a user clicks the findings count in the Scan History tab, nothing happens — the number is plain text. Users want to see only the findings for a specific completed scan.

## Solution

Make the findings count in Scan History a clickable button that switches to the Findings tab pre-filtered to that scan's findings.

## Changes

### 1. Backend — `web/backend/main.py`

Add `scan_id` to the `_finding_to_api` return dict:

```python
"scan_id": f.get("scan_id", ""),
```

Currently `scan_id` is stored in the DB (via `result_ingestion_engine.get_findings`) and passed through the ingestion pipeline, but `_finding_to_api` strips it before sending to the frontend. This single-line fix makes it available for client-side filtering.

### 2. Frontend — `web/frontend/src/pages/Results.jsx`

#### `Results` component

Add `scanFilter` state (`null` or `{ id: string, target: string }`). Pass `scanFilter`, `setScanFilter`, and `setTab` as props to both child tab components.

#### `ScanHistoryTab`

Receives `onViewFindings(scan)` prop. The findings count cell changes from plain text to a clickable button:

```jsx
<button
  className="text-accent-primary hover:underline"
  onClick={e => { e.stopPropagation(); onViewFindings(s) }}
>
  {s.findings_count ?? s.findings ?? 0}
</button>
```

`onViewFindings` calls `setScanFilter({ id: s.id, target: s.target })` then `setTab('findings')`.

Only shown as a link when the count is > 0.

#### `FindingsTab`

Receives `scanFilter` and `onClearFilter` props.

When `scanFilter` is set:
- Displays a dismissable context banner above the filter bar:
  ```
  [ShieldAlert icon] Findings for www.vulnbank.org (gm-be922d)  [× All Scans]
  ```
- Applies `v.scan_id === scanFilter.id` as a pre-filter before the existing severity/status/search filters
- Stats cards (Total, Critical, High, Confirmed) reflect the filtered subset only

When `scanFilter` is null: behaviour is identical to current (shows all findings).

`onClearFilter` calls `setScanFilter(null)`.

## Data Flow

```
ScanHistoryTab: user clicks "32"
  → onViewFindings({ id: 'gm-be922d', target: 'www.vulnbank.org' })
    → setScanFilter({ id: 'gm-be922d', target: 'www.vulnbank.org' })
    → setTab('findings')
      → FindingsTab renders with scanFilter set
        → vulnerabilities filtered by v.scan_id === 'gm-be922d'
        → context banner shown with × clear button
```

## What Is Not Changed

- No new API endpoints — the `vulnerabilities` store already carries all findings and refreshes every 10s via `App.jsx`'s `setInterval`
- No URL changes — this is in-page state
- No store changes — `scanFilter` is local to `Results`
- The existing severity/status/text search filters continue to work within the scan-scoped subset

## Scope

- `web/backend/main.py`: 1 line added to `_finding_to_api`
- `web/frontend/src/pages/Results.jsx`: `Results`, `FindingsTab`, `ScanHistoryTab` components modified
- No other files touched
