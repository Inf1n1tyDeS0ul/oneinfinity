# OneInfinity — Production SaaS Platform Transformation
**Date:** 2026-03-28
**Approach:** Option A — Incremental in-place enhancement
**Stack:** Vite + React 18 + Tailwind v3 (unchanged)

---

## Architecture Overview

All changes stay within the existing frontend stack. No framework migrations.

### New Files
- `src/components/ui/Skeleton.jsx` — pulse placeholder component
- `src/components/ui/CommandPalette.jsx` — Cmd+K modal with fuzzy search
- `src/components/ui/ErrorBoundary.jsx` — per-page crash boundary
- `src/components/ui/Breadcrumbs.jsx` — auto-generated route breadcrumbs
- `src/components/ui/DataTable.jsx` — sortable/filterable/paginated table
- `src/hooks/useTheme.js` — light/dark toggle with localStorage persistence
- `src/hooks/useLocalStorage.js` — thin hook for persisting UI state
- `src/hooks/useCommandPalette.js` — Cmd+K state + navigation registry
- `src/context/ThemeContext.jsx` — theme provider wrapping App

### Modified Files
- `tailwind.config.js` — CSS variable-based color tokens
- `src/index.css` — CSS variable definitions for both themes
- `src/components/Layout.jsx` — theme toggle, mobile drawer, breadcrumbs, Cmd+K trigger
- `src/App.jsx` — ErrorBoundary wrapping each route, ThemeProvider
- `src/utils/api.js` — enhanced error interceptor with toast + retry
- All 24 pages — skeleton loaders, DataTable adoption, empty states

---

## Phase 1 — Design System Foundation

### Light/Dark Mode
- CSS variables in `index.css` define both themes under `[data-theme="light"]` and `:root` (dark default)
- `tailwind.config.js` color tokens reference `var(--color-*)` instead of hard-coded hex values
- Toggle button in header writes `"light"|"dark"` to `localStorage` and sets `data-theme` on `<html>`
- Dark theme: unchanged from current (bg #07090f, accent #00d9ff)
- Light theme: bg white/slate-50, text slate-900, accent cyan-600

### Skeleton Loaders
- `<Skeleton>` component: `animate-pulse bg-bg-elevated rounded` with configurable width/height
- Applied on every page during API loading state
- Skeleton shapes match the actual content layout (stat card skeletons, table row skeletons, etc.)

### Animation Polish
- Page transitions: 150ms fade-in on route change via CSS `@keyframes fade-in`
- Card hover: `translateY(-1px)` + increased glow on `.card:hover`
- Consistent `transition-all duration-150` on all interactive elements
- Keep existing toast slide-in animation

### Spacing Standardization
- 8px grid enforced: `p-4` (compact), `p-6` (standard), `gap-4` (within sections), `gap-6` (between sections)
- All 24 pages audited and updated for consistency

---

## Phase 2 — Core UX Infrastructure

### Command Palette (Cmd+K)
- `<CommandPalette>` modal overlay, triggered by `Cmd+K` / `Ctrl+K` global keydown
- Contents: all 24 nav routes (searchable by label), recent scans (from store), quick actions
  - Quick actions: Launch Scan, Stop All, New Target, Toggle Theme
- Fuzzy search filters routes in real-time as user types
- Keyboard navigation: Arrow keys move selection, Enter navigates, Escape closes
- Rendered as a portal at document root to avoid z-index conflicts

### Error Boundaries
- `<ErrorBoundary>` wraps each `<Route>` element in `App.jsx`
- On crash: renders a card with error message + "Reload Page" button
- Does not crash the sidebar/header — only the page content area is affected

### Mobile-Responsive Sidebar
- Breakpoint: `< 768px` (Tailwind `md:`)
- Mobile: sidebar becomes a fixed overlay drawer, slides in from left
- Hamburger menu button appears in header on mobile (hidden on desktop)
- Backdrop (semi-transparent overlay) click closes the drawer
- Desktop: existing collapsible behavior (w-52 / w-14) unchanged

### Persistent UI State
- `useLocalStorage` hook: `const [value, setValue] = useLocalStorage(key, defaultValue)`
- Persisted: sidebar open/closed, console open/closed, selected tab per page (stored per-page key)
- On first visit: defaults apply. On revisit: last state restores.

### Breadcrumbs
- `<Breadcrumbs>` bar rendered below the header, above `<main>`
- Auto-generated from `useLocation()` — splits pathname into segments, maps to human-readable labels
- Clickable segments for parent navigation
- Hidden on `/dashboard` (root page — no parent context needed)
- Height: 32px, text: 11px slate-500, separator: `/`

---

## Phase 3 — Data Layer

### DataTable Component
- Props: `columns` (array of `{ key, label, sortable, render }`), `data` (array), `searchable` (bool), `pageSize` (default 25)
- Features:
  - Column sorting: click header toggles asc → desc → none
  - Search input: filters all string columns client-side
  - Pagination: page selector + prev/next + rows-per-page dropdown (10/25/50)
  - Loading state: renders skeleton rows when `loading` prop is true
  - Empty state: renders centered message + action when `data` is empty
- Adopted across: Results, Targets, Traffic, Secrets, AI Models history, Reports, Bounty Hunter findings

### Form Validation
- Inline validation on all forms: ScanLauncher, Add Target, GodMode launch, CVSS Calculator
- Rules enforced:
  - Required fields: red border + error message below on blur
  - URL fields: must match URL pattern
  - Numeric fields: must be within stated range
- Submit button disabled until all required fields are valid
- Implementation: React state only (no external library needed at this complexity)

### API Error Handling
- Global axios response interceptor enhanced:
  - 4xx/5xx: fires `addNotification({ type: 'error', msg: response.data.detail || statusText })`
  - Network offline: sets a store flag `apiOffline: true`
- Status bar: "API Connected" replaced with "API Offline" (red) when `apiOffline` is true
- GET request errors include a Retry button on the toast (re-fires the same request)

### Empty States
- Every list/table with possible empty data gets:
  - Centered icon (relevant Lucide icon, size 32, slate-600)
  - Message: e.g., "No targets yet"
  - Primary action button: e.g., "Add your first target"
- Pages covered: Targets, Results, Traffic, Secrets, Reports, Bounty Hunter, AI Models history

---

## Phase 4 — Intelligence UX

### Neo4j Attack Path Visualization
- `AttackGraphPage` side panel: clicking any node opens a right-side details panel
  - Shows: node type, risk score, connected vulnerability count, last seen
  - "Expand neighbors" button loads adjacent nodes
- Attack paths: edges on critical paths rendered red with animated stroke-dashoffset
- "Critical Paths Only" toggle: hides non-critical edges
- Node sizing: `radius` proportional to risk score (min 4px, max 16px)

### Swarm Confidence Scores
- `SwarmIntelligence` page: each agent result row shows a confidence badge
  - Color: green (>80%), yellow (50–80%), red (<50%)
  - Value sourced from existing agent result payload (add `confidence` field rendering)
- Mini sparkline (5-point Recharts LineChart, no axes) shows confidence trend per agent

### Adaptive Recon "Why" Panel
- `Research` and `GodMode` pages: collapsible panel at top of content
- Pulls from `/api/brain/priorities` endpoint (already implemented)
- Renders: "Target ranked #1 because: [reason list]"
- Collapsed by default, expands on click, persists open/closed state via `useLocalStorage`

### God Mode Mission Timeline
- Replace current mission pipeline badges with a proper vertical timeline
- Each mission entry: start time, duration, findings count, mini log preview (last 3 lines)
- Clicking a mission row expands its full log inline (no tab switch needed)
- Running mission: animated pulse border

### Real-Time Swarm Activity Grid
- `SwarmIntelligence` page: 8 agent cards in a 4×2 grid
  - Agents: xss, sqli, ssrf, idor, auth, biz_logic, mobile, api
  - Each card: status dot (idle/running/done), agent name, last target, findings this session
- Updates via existing WebSocket connection — no additional polling needed
- Status dot colors: cyan (running), green (done), slate (idle), red (error)

---

## Success Criteria

- [ ] Light/dark mode toggle works with no page reload
- [ ] All pages show skeleton loaders during data fetch
- [ ] Cmd+K opens command palette and navigates correctly
- [ ] Sidebar collapses to drawer on mobile (<768px)
- [ ] All list views support sort + filter + pagination
- [ ] Form submissions show inline validation errors
- [ ] API errors surface as toasts; offline state shown in status bar
- [ ] Empty states present on all list pages
- [ ] Attack graph nodes show detail panel on click
- [ ] God Mode shows expandable per-mission logs
- [ ] No console errors in production build
- [ ] `npm run build` succeeds without warnings
