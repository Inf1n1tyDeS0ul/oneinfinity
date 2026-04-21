# OneInfinity SaaS Platform Transformation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the OneInfinity frontend into a production-grade SaaS security platform across 4 phases: design system, UX infrastructure, data layer, and intelligence UX.

**Architecture:** Incremental in-place enhancement of the existing Vite + React 18 + Tailwind v3 stack. New shared UI primitives live in `src/components/ui/`. New hooks in `src/hooks/`. No framework migrations.

**Tech Stack:** React 18, Vite 5, Tailwind CSS v3, Zustand, Axios, Lucide React, Recharts, react-force-graph-2d, Vitest + React Testing Library (added in Task 1)

---

## File Map

### New files
- `src/components/ui/Skeleton.jsx` — pulse placeholder, configurable size
- `src/components/ui/CommandPalette.jsx` — Cmd+K modal with fuzzy search + keyboard nav
- `src/components/ui/ErrorBoundary.jsx` — per-route crash boundary
- `src/components/ui/Breadcrumbs.jsx` — auto-generated from route path
- `src/components/ui/DataTable.jsx` — sortable / filterable / paginated table
- `src/hooks/useLocalStorage.js` — thin localStorage hook
- `src/hooks/useTheme.js` — light/dark toggle, syncs to `data-theme` on `<html>`
- `src/context/ThemeContext.jsx` — context + provider, wraps App
- `src/test/setup.js` — Vitest global setup

### Modified files
- `package.json` — add vitest, @vitest/ui, @testing-library/react, @testing-library/jest-dom, jsdom
- `vite.config.js` — add test config block
- `tailwind.config.js` — replace hard-coded hex values with `var(--color-*)` references
- `src/index.css` — add CSS variable blocks for dark (`:root`) and light (`[data-theme="light"]`) themes; add `.skeleton` class; add `.input-error` and `.field-error` classes
- `src/store/useStore.js` — add `apiOffline` flag + `setApiOffline` action
- `src/utils/api.js` — enhance interceptor: toast on 4xx/5xx, set `apiOffline` on network error
- `src/App.jsx` — wrap routes in `<ErrorBoundary>`, wrap root in `<ThemeProvider>`
- `src/components/Layout.jsx` — add theme toggle button, hamburger for mobile, `<Breadcrumbs>`, `<CommandPalette>`, mobile drawer overlay, status bar offline indicator
- `src/components/ScanLauncher.jsx` — inline validation on required fields
- `src/pages/GodMode.jsx` — inline validation, vertical mission timeline, "Why" panel
- `src/pages/Targets.jsx` — adopt `<DataTable>`, add empty state
- `src/pages/Results.jsx` — adopt `<DataTable>`, add empty state
- `src/pages/TrafficExplorer.jsx` — adopt `<DataTable>` for traffic list, add empty state
- `src/pages/SecretDashboard.jsx` — adopt `<DataTable>`, add empty state
- `src/pages/AIModels.jsx` — adopt `<DataTable>` for history tab, add empty state
- `src/pages/BountyHunter.jsx` — adopt `<DataTable>` for findings, add empty state
- `src/pages/Reports.jsx` — adopt `<DataTable>` for saved reports, add empty state
- `src/pages/AttackGraph.jsx` — node detail side panel, critical-path highlighting, node sizing
- `src/pages/SwarmIntelligence.jsx` — 8-agent real-time grid, confidence score badges
- `src/pages/Research.jsx` — "Why" panel pulling from `/api/brain/priorities`

---

## Task 1: Add Vitest + React Testing Library

**Files:**
- Modify: `package.json`
- Create: `vite.config.js` (currently does not exist — Vite uses defaults)
- Create: `src/test/setup.js`

- [ ] **Step 1: Install test dependencies**

```bash
cd /path/to/oneinfinity/web/frontend
npm install --save-dev vitest @vitest/ui jsdom @testing-library/react @testing-library/jest-dom @testing-library/user-event
```

Expected: packages added to `node_modules`, no errors.

- [ ] **Step 2: Create vite.config.js**

```js
// web/frontend/vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/ws':  { target: 'ws://localhost:8000',  ws: true },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.js',
  },
})
```

- [ ] **Step 3: Create test setup file**

```js
// web/frontend/src/test/setup.js
import '@testing-library/jest-dom'
```

- [ ] **Step 4: Add test script to package.json**

Open `package.json` and add to `"scripts"`:
```json
"test": "vitest run",
"test:watch": "vitest"
```

- [ ] **Step 5: Verify test runner works**

```bash
cd /path/to/oneinfinity/web/frontend
npm test
```

Expected: "No test files found" (passes with 0 tests — confirms setup works).

- [ ] **Step 6: Commit**

```bash
cd /path/to/oneinfinity/web/frontend
git add package.json vite.config.js src/test/setup.js
git commit -m "chore: add Vitest + React Testing Library"
```

---

## Task 2: CSS Variable Theming System

**Files:**
- Modify: `tailwind.config.js`
- Modify: `src/index.css`

- [ ] **Step 1: Update tailwind.config.js to use CSS variables**

Replace the `colors` block in `tailwind.config.js` with:

```js
// web/frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary:   'var(--color-bg-primary)',
          secondary: 'var(--color-bg-secondary)',
          card:      'var(--color-bg-card)',
          elevated:  'var(--color-bg-elevated)',
          border:    'var(--color-bg-border)',
          muted:     'var(--color-bg-muted)',
        },
        accent: {
          primary:   'var(--color-accent-primary)',
          secondary: 'var(--color-accent-secondary)',
          success:   '#10b981',
          warn:      '#f59e0b',
          danger:    '#ef4444',
          purple:    '#a855f7',
          orange:    '#f97316',
          pink:      '#ec4899',
          lime:      '#84cc16',
        },
        text: {
          primary:   'var(--color-text-primary)',
          secondary: 'var(--color-text-secondary)',
          muted:     'var(--color-text-muted)',
        },
        sev: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#f59e0b',
          low:      '#3b82f6',
          info:     '#6b7280',
        },
        neon: {
          cyan:   '#00d9ff',
          green:  '#00ff87',
          purple: '#b400ff',
          red:    '#ff0040',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', { lineHeight: '14px' }],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic':  'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'cyber-grid':      'linear-gradient(rgba(0,217,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,217,255,0.03) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid-40': '40px 40px',
      },
      boxShadow: {
        'glow-cyan':   '0 0 20px rgba(0, 217, 255, 0.15), 0 0 40px rgba(0, 217, 255, 0.05)',
        'glow-red':    '0 0 20px rgba(239, 68, 68, 0.15)',
        'glow-green':  '0 0 20px rgba(16, 185, 129, 0.15)',
        'glow-purple': '0 0 20px rgba(99, 102, 241, 0.15)',
        'glow-orange': '0 0 20px rgba(249, 115, 22, 0.15)',
        'card':        '0 1px 3px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03)',
        'card-hover':  '0 4px 12px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,217,255,0.1)',
        'modal':       '0 25px 50px rgba(0,0,0,0.8), 0 0 80px rgba(0,217,255,0.05)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line':  'scan-line 2s linear infinite',
        'flicker':    'flicker 4s linear infinite',
        'fade-in':    'fade-in 0.15s ease-out',
        'slide-in':   'slide-in 0.2s ease-out',
      },
      keyframes: {
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'flicker': {
          '0%, 19%, 21%, 23%, 25%, 54%, 56%, 100%': { opacity: '1' },
          '20%, 24%, 55%': { opacity: '0.6' },
        },
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateX(16px)' },
          to:   { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
}
```

- [ ] **Step 2: Add CSS variable blocks to the top of src/index.css**

Prepend the following before the existing `@tailwind base;` line:

```css
/* ── Theme variables ──────────────────────────────────────── */
:root {
  --color-bg-primary:    #07090f;
  --color-bg-secondary:  #0c101b;
  --color-bg-card:       #0f1523;
  --color-bg-elevated:   #131c2e;
  --color-bg-border:     #1c2a42;
  --color-bg-muted:      #1a2540;
  --color-accent-primary:   #00d9ff;
  --color-accent-secondary: #6366f1;
  --color-text-primary:  #e2e8f0;
  --color-text-secondary:#94a3b8;
  --color-text-muted:    #64748b;
}

[data-theme="light"] {
  --color-bg-primary:    #f8fafc;
  --color-bg-secondary:  #f1f5f9;
  --color-bg-card:       #ffffff;
  --color-bg-elevated:   #f1f5f9;
  --color-bg-border:     #e2e8f0;
  --color-bg-muted:      #e2e8f0;
  --color-accent-primary:   #0891b2;
  --color-accent-secondary: #4f46e5;
  --color-text-primary:  #0f172a;
  --color-text-secondary:#475569;
  --color-text-muted:    #94a3b8;
}
```

Also add these two utility classes to the `@layer components` block in `index.css`:

```css
  /* Form validation */
  .input-error { @apply border-red-500/60 focus:border-red-500/80 focus:ring-red-500/20; }
  .field-error  { @apply text-xs text-red-400 mt-1; }

  /* Skeleton */
  .skeleton { @apply animate-pulse bg-bg-elevated rounded; }
```

Also update the `body` rule in `@layer base` to use CSS variable text color:

```css
  body {
    @apply bg-bg-primary font-sans antialiased;
    color: var(--color-text-primary);
    font-size: 14px;
  }
```

- [ ] **Step 3: Verify build still passes**

```bash
cd /path/to/oneinfinity/web/frontend
npm run build 2>&1 | tail -5
```

Expected: `✓ built in` with no errors.

- [ ] **Step 4: Commit**

```bash
git add tailwind.config.js src/index.css
git commit -m "feat(theme): CSS variable token system for light/dark mode"
```

---

## Task 3: useLocalStorage Hook + useTheme Hook + ThemeContext

**Files:**
- Create: `src/hooks/useLocalStorage.js`
- Create: `src/hooks/useTheme.js`
- Create: `src/context/ThemeContext.jsx`
- Create: `src/hooks/__tests__/useLocalStorage.test.js`

- [ ] **Step 1: Write the failing test for useLocalStorage**

```js
// web/frontend/src/hooks/__tests__/useLocalStorage.test.js
import { renderHook, act } from '@testing-library/react'
import { useLocalStorage } from '../useLocalStorage'

beforeEach(() => localStorage.clear())

test('returns default value when key not set', () => {
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  expect(result.current[0]).toBe('default')
})

test('persists value to localStorage', () => {
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  act(() => result.current[1]('updated'))
  expect(localStorage.getItem('key')).toBe('"updated"')
  expect(result.current[0]).toBe('updated')
})

test('reads existing localStorage value on mount', () => {
  localStorage.setItem('key', '"existing"')
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  expect(result.current[0]).toBe('existing')
})
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /path/to/oneinfinity/web/frontend
npm test -- src/hooks/__tests__/useLocalStorage.test.js
```

Expected: FAIL — "Cannot find module '../useLocalStorage'"

- [ ] **Step 3: Implement useLocalStorage**

```js
// web/frontend/src/hooks/useLocalStorage.js
import { useState } from 'react'

export function useLocalStorage(key, defaultValue) {
  const [value, setValue] = useState(() => {
    try {
      const item = localStorage.getItem(key)
      return item !== null ? JSON.parse(item) : defaultValue
    } catch {
      return defaultValue
    }
  })

  const setStored = (newValue) => {
    setValue(newValue)
    try {
      localStorage.setItem(key, JSON.stringify(newValue))
    } catch {
      // quota exceeded or private browsing — silent fail
    }
  }

  return [value, setStored]
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
npm test -- src/hooks/__tests__/useLocalStorage.test.js
```

Expected: PASS — 3 tests.

- [ ] **Step 5: Implement useTheme**

```js
// web/frontend/src/hooks/useTheme.js
import { useContext } from 'react'
import { ThemeContext } from '../context/ThemeContext'

export function useTheme() {
  return useContext(ThemeContext)
}
```

- [ ] **Step 6: Implement ThemeContext**

```jsx
// web/frontend/src/context/ThemeContext.jsx
import React, { createContext, useEffect } from 'react'
import { useLocalStorage } from '../hooks/useLocalStorage'

export const ThemeContext = createContext({ theme: 'dark', toggleTheme: () => {} })

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useLocalStorage('ui-theme', 'dark')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark')

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}
```

- [ ] **Step 7: Commit**

```bash
git add src/hooks/useLocalStorage.js src/hooks/__tests__/useLocalStorage.test.js src/hooks/useTheme.js src/context/ThemeContext.jsx
git commit -m "feat(theme): useLocalStorage, useTheme hooks, ThemeContext provider"
```

---

## Task 4: Skeleton Component

**Files:**
- Create: `src/components/ui/Skeleton.jsx`
- Create: `src/components/ui/__tests__/Skeleton.test.jsx`

- [ ] **Step 1: Write the failing test**

```jsx
// web/frontend/src/components/ui/__tests__/Skeleton.test.jsx
import { render } from '@testing-library/react'
import { Skeleton, SkeletonTable, SkeletonCard } from '../Skeleton'

test('Skeleton renders with default classes', () => {
  const { container } = render(<Skeleton />)
  const el = container.firstChild
  expect(el).toHaveClass('skeleton')
  expect(el).toHaveClass('h-4')
  expect(el).toHaveClass('w-full')
})

test('Skeleton accepts custom className', () => {
  const { container } = render(<Skeleton className="w-24 h-6" />)
  expect(container.firstChild).toHaveClass('w-24', 'h-6')
})

test('SkeletonTable renders correct number of rows', () => {
  const { getAllByRole } = render(<SkeletonTable rows={3} cols={4} />)
  // 3 rows × 4 cells = 12 cells rendered as list items
  expect(getAllByRole('listitem')).toHaveLength(3)
})

test('SkeletonCard renders', () => {
  const { container } = render(<SkeletonCard />)
  expect(container.firstChild).toBeTruthy()
})
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npm test -- src/components/ui/__tests__/Skeleton.test.jsx
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement Skeleton component**

```jsx
// web/frontend/src/components/ui/Skeleton.jsx
import React from 'react'
import clsx from 'clsx'

export function Skeleton({ className }) {
  return <div role="listitem" className={clsx('skeleton h-4 w-full', className)} />
}

export function SkeletonTable({ rows = 5, cols = 4 }) {
  return (
    <div className="w-full">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} role="listitem" className="flex gap-3 px-4 py-3 border-b border-bg-border/50">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className={clsx('h-3', j === 0 ? 'w-32' : j === cols - 1 ? 'w-16' : 'flex-1')} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonCard() {
  return (
    <div className="card p-5 flex flex-col gap-3">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export function SkeletonStatGrid({ count = 4 }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  )
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
npm test -- src/components/ui/__tests__/Skeleton.test.jsx
```

Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/components/ui/Skeleton.jsx src/components/ui/__tests__/Skeleton.test.jsx
git commit -m "feat(ui): Skeleton, SkeletonTable, SkeletonCard, SkeletonStatGrid components"
```

---

## Task 5: ErrorBoundary Component

**Files:**
- Create: `src/components/ui/ErrorBoundary.jsx`

- [ ] **Step 1: Implement ErrorBoundary**

React error boundaries must be class components — no test required for the class itself, but verify it renders children normally.

```jsx
// web/frontend/src/components/ui/ErrorBoundary.jsx
import React from 'react'
import { AlertTriangle } from 'lucide-react'

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary]', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full py-24 gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <AlertTriangle size={20} className="text-red-400" />
          </div>
          <div className="text-center">
            <p className="text-sm font-medium text-slate-300">Something went wrong</p>
            <p className="text-xs text-slate-500 mt-1 max-w-xs font-mono">
              {this.state.error?.message || 'Unknown error'}
            </p>
          </div>
          <button
            className="btn-secondary"
            onClick={() => window.location.reload()}
          >
            Reload Page
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
```

- [ ] **Step 2: Wrap all routes in App.jsx with ErrorBoundary and ThemeProvider**

Read current `src/App.jsx`, then update it:

```jsx
// Add these imports at the top of src/App.jsx (after existing imports):
import { ThemeProvider } from './context/ThemeContext'
import { ErrorBoundary } from './components/ui/ErrorBoundary'
```

Wrap the `<Layout>` return in ThemeProvider:

```jsx
return (
  <ThemeProvider>
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard"      element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
        <Route path="/targets"        element={<ErrorBoundary><Targets /></ErrorBoundary>} />
        <Route path="/results"        element={<ErrorBoundary><Results /></ErrorBoundary>} />
        <Route path="/attack-graph"   element={<ErrorBoundary><AttackGraphPage /></ErrorBoundary>} />
        <Route path="/system"         element={<ErrorBoundary><SystemControl /></ErrorBoundary>} />
        <Route path="/traffic"        element={<ErrorBoundary><TrafficExplorer /></ErrorBoundary>} />
        <Route path="/chains/:scanId" element={<ErrorBoundary><ExploitChainViewer /></ErrorBoundary>} />
        <Route path="/chains"         element={<ErrorBoundary><ExploitChainViewer /></ErrorBoundary>} />
        <Route path="/brain"          element={<ErrorBoundary><BrainDashboard /></ErrorBoundary>} />
        <Route path="/intelligence"   element={<ErrorBoundary><LiveIntelligence /></ErrorBoundary>} />
        <Route path="/swarm"          element={<ErrorBoundary><SwarmIntelligence /></ErrorBoundary>} />
        <Route path="/evolution"      element={<ErrorBoundary><SystemEvolution /></ErrorBoundary>} />
        <Route path="/orchestrator"   element={<ErrorBoundary><OrchestratorPanel /></ErrorBoundary>} />
        <Route path="/mobile"         element={<ErrorBoundary><MobileSecurity /></ErrorBoundary>} />
        <Route path="/hunter"         element={<ErrorBoundary><BountyHunter /></ErrorBoundary>} />
        <Route path="/secrets"        element={<ErrorBoundary><SecretDashboard /></ErrorBoundary>} />
        <Route path="/god-mode"       element={<ErrorBoundary><GodMode /></ErrorBoundary>} />
        <Route path="/research"       element={<ErrorBoundary><Research /></ErrorBoundary>} />
        <Route path="/tools"          element={<ErrorBoundary><Tools /></ErrorBoundary>} />
        <Route path="/ai-ops"         element={<ErrorBoundary><AIModels /></ErrorBoundary>} />
        <Route path="/learning"       element={<ErrorBoundary><Learning /></ErrorBoundary>} />
        <Route path="/simulation"     element={<ErrorBoundary><Simulation /></ErrorBoundary>} />
        <Route path="/utilities"      element={<ErrorBoundary><Utilities /></ErrorBoundary>} />
        <Route path="/reports"        element={<ErrorBoundary><Reports /></ErrorBoundary>} />
        <Route path="/infrastructure" element={<ErrorBoundary><Infrastructure /></ErrorBoundary>} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  </ThemeProvider>
)
```

- [ ] **Step 3: Verify build**

```bash
npm run build 2>&1 | tail -5
```

Expected: builds without errors.

- [ ] **Step 4: Commit**

```bash
git add src/components/ui/ErrorBoundary.jsx src/App.jsx
git commit -m "feat(ui): ErrorBoundary per-route, ThemeProvider wrapping App"
```

---

## Task 6: Breadcrumbs Component

**Files:**
- Create: `src/components/ui/Breadcrumbs.jsx`

- [ ] **Step 1: Implement Breadcrumbs**

```jsx
// web/frontend/src/components/ui/Breadcrumbs.jsx
import React from 'react'
import { useLocation, Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

const ROUTE_LABELS = {
  dashboard:      'Dashboard',
  targets:        'Targets',
  results:        'Findings',
  'attack-graph': 'Attack Graph',
  system:         'System Control',
  traffic:        'Traffic',
  chains:         'Exploit Chains',
  brain:          'Graph Brain',
  intelligence:   'Live Intel',
  swarm:          'Swarm',
  evolution:      'Evolution',
  orchestrator:   'Orchestrator',
  mobile:         'Mobile Security',
  hunter:         'Bounty Hunter',
  secrets:        'Secrets',
  'god-mode':     'GOD MODE',
  research:       'Research',
  tools:          'Tools & Plugins',
  'ai-ops':       'AI Models',
  learning:       'Learning',
  simulation:     'Simulation',
  utilities:      'Utilities',
  reports:        'Reports',
  infrastructure: 'Infrastructure',
}

export function Breadcrumbs() {
  const { pathname } = useLocation()

  // Hide on dashboard — no parent context
  if (pathname === '/dashboard' || pathname === '/') return null

  const segments = pathname.split('/').filter(Boolean)

  return (
    <nav className="flex items-center h-8 px-5 border-b border-bg-border gap-1.5 text-[11px] text-slate-500 flex-shrink-0">
      <Link to="/dashboard" className="hover:text-slate-300 transition-colors">
        Home
      </Link>
      {segments.map((seg, i) => {
        const path = '/' + segments.slice(0, i + 1).join('/')
        const label = ROUTE_LABELS[seg] || seg
        const isLast = i === segments.length - 1
        return (
          <React.Fragment key={path}>
            <ChevronRight size={10} className="text-slate-700" />
            {isLast ? (
              <span className="text-slate-300 font-medium">{label}</span>
            ) : (
              <Link to={path} className="hover:text-slate-300 transition-colors">
                {label}
              </Link>
            )}
          </React.Fragment>
        )
      })}
    </nav>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add src/components/ui/Breadcrumbs.jsx
git commit -m "feat(ui): Breadcrumbs auto-generated from route path"
```

---

## Task 7: CommandPalette Component

**Files:**
- Create: `src/components/ui/CommandPalette.jsx`

- [ ] **Step 1: Implement CommandPalette**

```jsx
// web/frontend/src/components/ui/CommandPalette.jsx
import React, { useState, useEffect, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { Search, LayoutDashboard, Target, ShieldAlert, Share2, Zap,
         Settings, Terminal, Brain, Activity, Users, GitBranch, Cpu,
         Smartphone, Trophy, Key, FlaskConical, Wrench, BarChart3,
         BookOpen, Network, Bot, Boxes, Telescope, TrendingUp,
         FileText, ServerCog, Flame, X } from 'lucide-react'
import clsx from 'clsx'

const ALL_ROUTES = [
  { path: '/dashboard',      label: 'Dashboard',        icon: LayoutDashboard, group: 'Operations' },
  { path: '/god-mode',       label: 'GOD MODE',         icon: Flame,           group: 'Operations' },
  { path: '/targets',        label: 'Targets',          icon: Target,          group: 'Operations' },
  { path: '/hunter',         label: 'Bounty Hunter',    icon: Trophy,          group: 'Operations' },
  { path: '/results',        label: 'Findings',         icon: ShieldAlert,     group: 'Analysis' },
  { path: '/attack-graph',   label: 'Attack Graph',     icon: Share2,          group: 'Analysis' },
  { path: '/chains',         label: 'Exploit Chains',   icon: Zap,             group: 'Analysis' },
  { path: '/traffic',        label: 'Traffic',          icon: Network,         group: 'Analysis' },
  { path: '/secrets',        label: 'Secrets',          icon: Key,             group: 'Analysis' },
  { path: '/intelligence',   label: 'Live Intel',       icon: Telescope,       group: 'Intelligence' },
  { path: '/research',       label: 'Research',         icon: FlaskConical,    group: 'Intelligence' },
  { path: '/simulation',     label: 'Simulation',       icon: TrendingUp,      group: 'Intelligence' },
  { path: '/learning',       label: 'Learning',         icon: BookOpen,        group: 'Intelligence' },
  { path: '/swarm',          label: 'Swarm',            icon: Users,           group: 'Agents & AI' },
  { path: '/brain',          label: 'Graph Brain',      icon: Brain,           group: 'Agents & AI' },
  { path: '/ai-ops',         label: 'AI Models',        icon: Bot,             group: 'Agents & AI' },
  { path: '/orchestrator',   label: 'Orchestrator',     icon: Boxes,           group: 'Agents & AI' },
  { path: '/mobile',         label: 'Mobile Security',  icon: Smartphone,      group: 'Platform' },
  { path: '/tools',          label: 'Tools & Plugins',  icon: Wrench,          group: 'Platform' },
  { path: '/reports',        label: 'Reports',          icon: FileText,        group: 'Platform' },
  { path: '/utilities',      label: 'Utilities',        icon: BarChart3,       group: 'Platform' },
  { path: '/evolution',      label: 'Evolution',        icon: GitBranch,       group: 'System' },
  { path: '/infrastructure', label: 'Infrastructure',   icon: ServerCog,       group: 'System' },
  { path: '/system',         label: 'System Control',   icon: Settings,        group: 'System' },
]

export function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const navigate = useNavigate()
  const inputRef = useRef(null)

  const filtered = query.trim()
    ? ALL_ROUTES.filter(r =>
        r.label.toLowerCase().includes(query.toLowerCase()) ||
        r.group.toLowerCase().includes(query.toLowerCase())
      )
    : ALL_ROUTES

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  useEffect(() => { setSelected(0) }, [query])

  const go = useCallback((path) => {
    navigate(path)
    onClose()
  }, [navigate, onClose])

  const handleKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, filtered.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
    if (e.key === 'Enter')     { e.preventDefault(); if (filtered[selected]) go(filtered[selected].path) }
    if (e.key === 'Escape')    { onClose() }
  }

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-xl bg-bg-secondary border border-bg-border rounded-2xl shadow-modal overflow-hidden animate-fade-in"
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-bg-border">
          <Search size={15} className="text-slate-500 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search pages..."
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-500 outline-none"
          />
          <kbd className="text-[10px] text-slate-600 bg-bg-elevated border border-bg-border rounded px-1.5 py-0.5 font-mono">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <p className="text-center text-xs text-slate-600 py-8">No results for "{query}"</p>
          ) : (
            filtered.map((route, i) => {
              const Icon = route.icon
              return (
                <button
                  key={route.path}
                  className={clsx(
                    'w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors duration-100',
                    i === selected ? 'bg-accent-primary/10 text-accent-primary' : 'text-slate-300 hover:bg-white/5'
                  )}
                  onClick={() => go(route.path)}
                  onMouseEnter={() => setSelected(i)}
                >
                  <Icon size={14} className="flex-shrink-0 opacity-70" />
                  <span className="flex-1 text-sm">{route.label}</span>
                  <span className="text-[10px] text-slate-600">{route.group}</span>
                </button>
              )
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 px-4 py-2 border-t border-bg-border text-[10px] text-slate-600">
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">↵</kbd> open</span>
          <span><kbd className="font-mono">esc</kbd> close</span>
        </div>
      </div>
    </div>,
    document.body
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add src/components/ui/CommandPalette.jsx
git commit -m "feat(ui): CommandPalette with fuzzy search + keyboard navigation"
```

---

## Task 8: Update Layout (Theme Toggle, Mobile Drawer, Breadcrumbs, Cmd+K)

**Files:**
- Modify: `src/components/Layout.jsx`
- Modify: `src/store/useStore.js`

- [ ] **Step 1: Add apiOffline to store**

In `src/store/useStore.js`, add to the state and actions:

```js
// In the create((set, get) => ({ ... })) object, add:
apiOffline: false,
setApiOffline: (v) => set({ apiOffline: v }),
```

- [ ] **Step 2: Rewrite Layout.jsx**

Read current `src/components/Layout.jsx` fully first, then replace with:

```jsx
// web/frontend/src/components/Layout.jsx
import React, { useState, useEffect } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Share2, ShieldAlert, Target,
  Bell, ChevronLeft, ChevronRight, Play, Zap, Terminal,
  AlertTriangle, CheckCircle2, Info, Brain, Activity,
  Users, GitBranch, Cpu, Smartphone, Trophy, Key,
  Search, FlaskConical, Wrench, BarChart3, Database,
  BookOpen, Network, Shield, Settings, Bot, Boxes,
  X, Telescope, TrendingUp, FileText, ServerCog,
  MemoryStick, Flame, Sun, Moon, Menu
} from 'lucide-react'
import { useStore } from '../store/useStore'
import { useTheme } from '../hooks/useTheme'
import { useLocalStorage } from '../hooks/useLocalStorage'
import { CommandPalette } from './ui/CommandPalette'
import { Breadcrumbs } from './ui/Breadcrumbs'
import ScanLauncher from './ScanLauncher'
import LogConsole from './LogConsole'
import clsx from 'clsx'

const NAV_GROUPS = [
  {
    label: 'Operations',
    items: [
      { path: '/dashboard',    label: 'Dashboard',      icon: LayoutDashboard },
      { path: '/god-mode',     label: 'GOD MODE',       icon: Flame, accent: true },
      { path: '/targets',      label: 'Targets',        icon: Target },
      { path: '/hunter',       label: 'Bounty Hunter',  icon: Trophy },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { path: '/results',      label: 'Findings',       icon: ShieldAlert },
      { path: '/attack-graph', label: 'Attack Graph',   icon: Share2 },
      { path: '/chains',       label: 'Exploit Chains', icon: Zap },
      { path: '/traffic',      label: 'Traffic',        icon: Network },
      { path: '/secrets',      label: 'Secrets',        icon: Key },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { path: '/intelligence', label: 'Live Intel',     icon: Telescope },
      { path: '/research',     label: 'Research',       icon: FlaskConical },
      { path: '/simulation',   label: 'Simulation',     icon: TrendingUp },
      { path: '/learning',     label: 'Learning',       icon: BookOpen },
    ],
  },
  {
    label: 'Agents & AI',
    items: [
      { path: '/swarm',        label: 'Swarm',          icon: Users },
      { path: '/brain',        label: 'Graph Brain',    icon: Brain },
      { path: '/ai-ops',       label: 'AI Models',      icon: Bot },
      { path: '/orchestrator', label: 'Orchestrator',   icon: Boxes },
    ],
  },
  {
    label: 'Platform',
    items: [
      { path: '/mobile',       label: 'Mobile Security', icon: Smartphone },
      { path: '/tools',        label: 'Tools & Plugins',icon: Wrench },
      { path: '/reports',      label: 'Reports',        icon: FileText },
      { path: '/utilities',    label: 'Utilities',      icon: BarChart3 },
    ],
  },
  {
    label: 'System',
    items: [
      { path: '/evolution',    label: 'Evolution',      icon: GitBranch },
      { path: '/infrastructure', label: 'Infrastructure', icon: ServerCog },
      { path: '/system',       label: 'System Control', icon: Settings },
    ],
  },
]

export default function Layout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useLocalStorage('sidebar-open', true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [launcherOpen, setLauncherOpen] = useState(false)
  const [consoleOpen, setConsoleOpen] = useLocalStorage('console-open', false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { targets, selectedTarget, setSelectedTarget, notifications, stats, apiOffline } = useStore()
  const { theme, toggleTheme } = useTheme()

  const activeScans = stats?.active_scans ?? 0

  // Global Cmd+K listener
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setPaletteOpen(p => !p)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Close mobile drawer on route change
  const location = useNavigate ? useNavigate() : null
  useEffect(() => { setMobileOpen(false) }, [])

  const SidebarContent = () => (
    <nav className="flex-1 py-2 overflow-y-auto overflow-x-hidden">
      {NAV_GROUPS.map(group => (
        <div key={group.label}>
          {sidebarOpen && (
            <div className="nav-group-label">{group.label}</div>
          )}
          {!sidebarOpen && group.label !== 'Operations' && (
            <div className="mx-3 my-1.5 border-t border-bg-border opacity-50" />
          )}
          {group.items.map(({ path, label, icon: Icon, accent }) => (
            <NavLink
              key={path}
              to={path}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) => isActive
                ? 'nav-item-active'
                : accent
                ? 'nav-item flex items-center gap-2.5 px-3 py-2 mx-2 rounded-lg text-sm transition-all duration-150 cursor-pointer select-none text-orange-400 hover:text-orange-300 hover:bg-orange-500/10'
                : 'nav-item-inactive'
              }
              title={!sidebarOpen ? label : undefined}
            >
              <Icon size={15} className={clsx('flex-shrink-0', accent && 'drop-shadow-[0_0_4px_rgba(251,146,60,0.8)]')} />
              {sidebarOpen && <span className={clsx('truncate text-sm', accent && 'font-semibold tracking-wide')}>{label}</span>}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  )

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-bg-primary">
      {/* ── Top Header ─────────────────────────────────────────── */}
      <header className="flex items-center gap-3 px-4 h-12 bg-bg-secondary border-b border-bg-border flex-shrink-0 z-20">
        {/* Mobile hamburger */}
        <button
          className="btn-icon md:hidden"
          onClick={() => setMobileOpen(true)}
          aria-label="Open menu"
        >
          <Menu size={16} />
        </button>

        {/* Logo */}
        <div className="flex items-center gap-2 mr-2 select-none">
          <div className="relative">
            <Zap size={16} className="text-accent-primary" style={{ filter: 'drop-shadow(0 0 6px rgba(0,217,255,0.8))' }} />
          </div>
          <span className="font-bold text-accent-primary text-sm tracking-[0.2em] uppercase font-mono">
            One<span className="text-accent-secondary">&amp;</span>Infinity
          </span>
        </div>

        <div className="w-px h-5 bg-bg-border mx-1 hidden md:block" />

        {/* Target selector */}
        <div className="hidden md:flex items-center gap-2">
          <span className="text-xs text-slate-500 font-medium">Target</span>
          <select
            className="bg-bg-elevated border border-bg-border rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-accent-primary/50 w-52 cursor-pointer transition-colors"
            value={selectedTarget || ''}
            onChange={e => setSelectedTarget(e.target.value || null)}
          >
            <option value="">— All Targets —</option>
            {targets.map(t => (
              <option key={t.id} value={t.domain}>{t.name} ({t.domain})</option>
            ))}
          </select>
        </div>

        {/* Launch Scan */}
        <button
          className="btn-primary btn-sm ml-1 h-7"
          onClick={() => setLauncherOpen(true)}
        >
          <Play size={10} />
          <span className="hidden sm:inline">Launch Scan</span>
        </button>

        {/* Cmd+K search trigger */}
        <button
          className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-bg-elevated border border-bg-border text-xs text-slate-500 hover:text-slate-300 hover:border-slate-600 transition-colors cursor-pointer"
          onClick={() => setPaletteOpen(true)}
          aria-label="Open command palette"
        >
          <Search size={11} />
          <span>Search</span>
          <kbd className="text-[10px] bg-bg-primary border border-bg-border rounded px-1 font-mono">⌘K</kbd>
        </button>

        {/* Autonomous mode badge */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-accent-primary/20 bg-accent-primary/5">
          <span className="status-dot-pulse" />
          <span className="text-xs text-accent-primary font-medium">Autonomous</span>
        </div>

        <div className="flex-1" />

        {/* Active scans indicator */}
        {activeScans > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
            <Activity size={11} className="text-cyan-400 animate-pulse" />
            <span className="text-xs text-cyan-400 font-medium">{activeScans} scanning</span>
          </div>
        )}

        {/* Stats quick view */}
        <div className="hidden lg:flex items-center gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1">
            <ShieldAlert size={11} className="text-red-400" />
            <span className="text-slate-300 font-medium">{stats?.total_vulnerabilities ?? 0}</span> vulns
          </span>
          <span className="flex items-center gap-1">
            <Target size={11} className="text-accent-secondary" />
            <span className="text-slate-300 font-medium">{stats?.total_targets ?? 0}</span> targets
          </span>
        </div>

        {/* Theme toggle */}
        <button
          className="btn-icon"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        {/* Notifications */}
        <button className="btn-icon relative" aria-label="Notifications">
          <Bell size={14} />
          {notifications.length > 0 && (
            <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-accent-danger" />
          )}
        </button>

        {/* Console toggle */}
        <button
          className="btn-icon"
          onClick={() => setConsoleOpen(!consoleOpen)}
          title="Toggle console"
          aria-label="Toggle console"
        >
          <Terminal size={14} className={consoleOpen ? 'text-accent-primary' : ''} />
        </button>
      </header>

      {/* ── Notification toasts ─────────────────────────────────── */}
      <div className="fixed top-14 right-4 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full">
        {notifications.map(n => (
          <div key={n.id} className={clsx(
            'toast pointer-events-auto',
            n.type === 'error' ? 'toast-error' :
            n.type === 'success' ? 'toast-success' :
            n.type === 'warn' ? 'toast-warn' :
            'toast-info'
          )}>
            {n.type === 'error'   ? <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" /> :
             n.type === 'success' ? <CheckCircle2  size={14} className="flex-shrink-0 mt-0.5 text-emerald-400" /> :
                                    <Info          size={14} className="flex-shrink-0 mt-0.5 text-cyan-400" />}
            <span className="text-sm leading-relaxed">{n.msg}</span>
          </div>
        ))}
      </div>

      {/* ── Body ────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Mobile sidebar drawer */}
        {mobileOpen && (
          <div className="fixed inset-0 z-40 md:hidden">
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
            <aside className="relative flex flex-col w-64 h-full bg-bg-secondary border-r border-bg-border">
              <div className="flex items-center justify-between px-4 h-12 border-b border-bg-border flex-shrink-0">
                <span className="font-bold text-accent-primary text-sm tracking-[0.2em] uppercase font-mono">
                  One<span className="text-accent-secondary">&amp;</span>Infinity
                </span>
                <button className="btn-icon" onClick={() => setMobileOpen(false)} aria-label="Close menu">
                  <X size={14} />
                </button>
              </div>
              <SidebarContent />
            </aside>
          </div>
        )}

        {/* Desktop sidebar */}
        <aside className={clsx(
          'hidden md:flex flex-col bg-bg-secondary border-r border-bg-border flex-shrink-0 transition-all duration-200',
          sidebarOpen ? 'w-52' : 'w-14'
        )}>
          <SidebarContent />
          <button
            className="flex items-center justify-center h-10 border-t border-bg-border text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
          </button>
        </aside>

        {/* Main content */}
        <div className="flex flex-col flex-1 overflow-hidden">
          <Breadcrumbs />
          <main className="flex-1 overflow-auto p-5 animate-fade-in">
            {children}
          </main>

          {/* Log Console */}
          {consoleOpen && (
            <div className="flex-shrink-0 border-t border-bg-border h-44">
              <div className="flex items-center gap-2 px-4 py-2 bg-bg-secondary border-b border-bg-border">
                <Terminal size={12} className="text-accent-primary" />
                <span className="text-xs font-medium text-slate-400 flex-1 font-mono">Console</span>
                <button className="btn-icon" onClick={() => setConsoleOpen(false)} aria-label="Close console">
                  <X size={12} />
                </button>
              </div>
              <LogConsole />
            </div>
          )}
        </div>
      </div>

      {/* ── Status bar ──────────────────────────────────────────── */}
      <div className="h-6 bg-bg-secondary border-t border-bg-border flex items-center px-4 gap-4 text-[10px] text-slate-600 flex-shrink-0">
        <span className="flex items-center gap-1">
          {apiOffline ? (
            <>
              <span className="status-dot-error" style={{ width: '6px', height: '6px' }} />
              <span className="text-red-400">API Offline</span>
            </>
          ) : (
            <>
              <span className="status-dot-online" style={{ width: '6px', height: '6px' }} />
              <span className="text-slate-500">API Connected</span>
            </>
          )}
        </span>
        <span className="text-slate-700">|</span>
        <span>Neo4j: <span className="text-slate-500">
          {stats?.neo4j_connected ? 'Connected' : 'Offline'}
        </span></span>
        <span className="text-slate-700">|</span>
        <span>Findings: <span className="text-slate-400 font-medium">{stats?.total_vulnerabilities ?? 0}</span></span>
        <span className="text-slate-700">|</span>
        <span>Targets: <span className="text-slate-400 font-medium">{stats?.total_targets ?? 0}</span></span>
        <div className="flex-1" />
        <span className="font-mono">One&amp;Infinity v2.0</span>
      </div>

      {/* Command Palette */}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />

      {/* Scan Launcher modal */}
      {launcherOpen && <ScanLauncher onClose={() => setLauncherOpen(false)} />}
    </div>
  )
}
```

- [ ] **Step 3: Verify the app renders**

```bash
cd /path/to/oneinfinity/web/frontend
npm run dev &
# Open http://localhost:3000 in browser
# Verify: theme toggle button appears in header (sun/moon icon)
# Verify: Cmd+K opens command palette
# Verify: breadcrumbs appear on non-dashboard pages
# Verify: on narrow viewport (<768px), hamburger appears and sidebar becomes drawer
```

- [ ] **Step 4: Commit**

```bash
git add src/components/Layout.jsx src/store/useStore.js
git commit -m "feat(layout): theme toggle, command palette, mobile drawer, breadcrumbs, persistent sidebar state"
```

---

## Task 9: Enhanced API Error Handling

**Files:**
- Modify: `src/utils/api.js`

- [ ] **Step 1: Update the axios interceptor**

Read current `src/utils/api.js`, then replace the `api.interceptors.response.use` block with:

```js
// In src/utils/api.js — replace the existing interceptors.response.use block:
api.interceptors.response.use(
  r => r,
  err => {
    const { useStore } = await import('../store/useStore') // lazy to avoid circular
    const store = useStore.getState()

    if (!err.response) {
      // Network error — mark API as offline
      store.setApiOffline(true)
    } else {
      store.setApiOffline(false)
      const msg = err.response.data?.detail || err.response.statusText || 'Request failed'
      store.addNotification(msg, 'error')
    }
    return Promise.reject(err)
  }
)
```

Note: dynamic `import()` inside the interceptor avoids the circular dependency between `api.js` (imported early) and `useStore.js`. The pattern works because the interceptor only fires at request time, not at module load time.

However, dynamic import inside a non-async function needs adjustment. Use the synchronous import pattern instead:

```js
// Replace the interceptors block in src/utils/api.js:
import { useStore } from '../store/useStore'

api.interceptors.response.use(
  r => {
    useStore.getState().setApiOffline(false)
    return r
  },
  err => {
    const store = useStore.getState()
    if (!err.response) {
      store.setApiOffline(true)
    } else {
      store.setApiOffline(false)
      const msg = err.response.data?.detail || err.response.statusText || 'Request failed'
      store.addNotification(msg, 'error')
    }
    console.error('API error:', err.response?.data || err.message)
    return Promise.reject(err)
  }
)
```

- [ ] **Step 2: Verify build**

```bash
npm run build 2>&1 | tail -5
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add src/utils/api.js
git commit -m "feat(api): toast on 4xx/5xx errors, apiOffline flag on network failure"
```

---

## Task 10: DataTable Component

**Files:**
- Create: `src/components/ui/DataTable.jsx`
- Create: `src/components/ui/__tests__/DataTable.test.jsx`

- [ ] **Step 1: Write failing tests**

```jsx
// web/frontend/src/components/ui/__tests__/DataTable.test.jsx
import { render, screen, fireEvent } from '@testing-library/react'
import { DataTable } from '../DataTable'

const COLS = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'severity', label: 'Severity', sortable: true },
]
const DATA = [
  { id: 1, name: 'Bravo', severity: 'high' },
  { id: 2, name: 'Alpha', severity: 'critical' },
  { id: 3, name: 'Charlie', severity: 'low' },
]

test('renders all rows', () => {
  render(<DataTable columns={COLS} data={DATA} />)
  expect(screen.getByText('Bravo')).toBeInTheDocument()
  expect(screen.getByText('Alpha')).toBeInTheDocument()
  expect(screen.getByText('Charlie')).toBeInTheDocument()
})

test('sorts ascending on header click', () => {
  render(<DataTable columns={COLS} data={DATA} />)
  fireEvent.click(screen.getByText('Name'))
  const cells = screen.getAllByRole('cell').filter(c => ['Alpha','Bravo','Charlie'].includes(c.textContent))
  expect(cells[0].textContent).toBe('Alpha')
  expect(cells[1].textContent).toBe('Bravo')
})

test('filters rows by search query', () => {
  render(<DataTable columns={COLS} data={DATA} searchable />)
  fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: 'alpha' } })
  expect(screen.getByText('Alpha')).toBeInTheDocument()
  expect(screen.queryByText('Bravo')).not.toBeInTheDocument()
})

test('shows empty state when no data', () => {
  render(<DataTable columns={COLS} data={[]} emptyMessage="Nothing here" />)
  expect(screen.getByText('Nothing here')).toBeInTheDocument()
})

test('shows loading skeletons when loading prop is true', () => {
  render(<DataTable columns={COLS} data={[]} loading />)
  // skeleton rows render as listitem roles from SkeletonTable
  expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0)
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npm test -- src/components/ui/__tests__/DataTable.test.jsx
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement DataTable**

```jsx
// web/frontend/src/components/ui/DataTable.jsx
import React, { useState, useMemo } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown, Search } from 'lucide-react'
import { SkeletonTable } from './Skeleton'
import clsx from 'clsx'

export function DataTable({
  columns,
  data,
  loading = false,
  searchable = false,
  pageSize: defaultPageSize = 25,
  emptyMessage = 'No data',
  emptyAction = null,
}) {
  const [sortKey, setSortKey] = useState(null)
  const [sortDir, setSortDir] = useState('asc') // 'asc' | 'desc'
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(defaultPageSize)

  const filtered = useMemo(() => {
    if (!query.trim()) return data
    const q = query.toLowerCase()
    return data.filter(row =>
      columns.some(col => String(row[col.key] ?? '').toLowerCase().includes(q))
    )
  }, [data, query, columns])

  const sorted = useMemo(() => {
    if (!sortKey) return filtered
    return [...filtered].sort((a, b) => {
      const av = String(a[sortKey] ?? '')
      const bv = String(b[sortKey] ?? '')
      return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av)
    })
  }, [filtered, sortKey, sortDir])

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize)

  const handleSort = (key) => {
    if (sortKey === key) {
      if (sortDir === 'asc') setSortDir('desc')
      else { setSortKey(null); setSortDir('asc') }
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
    setPage(1)
  }

  return (
    <div className="flex flex-col gap-3">
      {searchable && (
        <div className="relative">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={e => { setQuery(e.target.value); setPage(1) }}
            placeholder="Search..."
            className="input pl-8 text-xs h-8"
          />
        </div>
      )}

      <div className="card overflow-hidden">
        {loading ? (
          <SkeletonTable rows={5} cols={columns.length} />
        ) : paginated.length === 0 ? (
          <div className="empty-state">
            <p className="empty-title">{emptyMessage}</p>
            {emptyAction}
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                {columns.map(col => (
                  <th
                    key={col.key}
                    onClick={col.sortable ? () => handleSort(col.key) : undefined}
                    className={clsx(col.sortable && 'cursor-pointer hover:text-slate-300 select-none')}
                  >
                    <div className="flex items-center gap-1">
                      {col.label}
                      {col.sortable && (
                        sortKey === col.key
                          ? sortDir === 'asc' ? <ChevronUp size={10} /> : <ChevronDown size={10} />
                          : <ChevronsUpDown size={10} className="opacity-30" />
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paginated.map((row, i) => (
                <tr key={row.id ?? i}>
                  {columns.map(col => (
                    <td key={col.key}>
                      {col.render ? col.render(row[col.key], row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {!loading && sorted.length > 0 && (
        <div className="flex items-center justify-between text-xs text-slate-500">
          <span>{sorted.length} item{sorted.length !== 1 ? 's' : ''}</span>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span>Rows:</span>
              <select
                value={pageSize}
                onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
                className="bg-bg-elevated border border-bg-border rounded px-1.5 py-0.5 text-xs text-slate-300 cursor-pointer"
              >
                {[10, 25, 50].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-1">
              <button
                className="btn-icon py-0.5 px-1.5 text-xs disabled:opacity-30"
                disabled={page === 1}
                onClick={() => setPage(p => p - 1)}
              >
                ‹
              </button>
              <span className="px-2">{page} / {totalPages}</span>
              <button
                className="btn-icon py-0.5 px-1.5 text-xs disabled:opacity-30"
                disabled={page === totalPages}
                onClick={() => setPage(p => p + 1)}
              >
                ›
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npm test -- src/components/ui/__tests__/DataTable.test.jsx
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/components/ui/DataTable.jsx src/components/ui/__tests__/DataTable.test.jsx
git commit -m "feat(ui): DataTable with sort, filter, pagination, loading, empty states"
```

---

## Task 11: Adopt DataTable in Pages (Targets, Results, Traffic, Secrets, BountyHunter, AIModels, Reports)

For each page below, the pattern is identical:
1. Import `DataTable` from `'../components/ui/DataTable'`
2. Define a `COLUMNS` array
3. Replace the raw `<table className="data-table">` block with `<DataTable columns={COLUMNS} data={items} searchable loading={loading} />`
4. Add `loading` state wired to the API call

### Targets page

- [ ] **Step 1: Update src/pages/Targets.jsx**

Read the file first, then apply the pattern. The columns for targets are:

```jsx
// Add to src/pages/Targets.jsx
import { DataTable } from '../components/ui/DataTable'

const COLUMNS = [
  { key: 'name',    label: 'Name',   sortable: true },
  { key: 'domain',  label: 'Domain', sortable: true },
  { key: 'type',    label: 'Type',   sortable: true },
  { key: 'status',  label: 'Status', sortable: true,
    render: (v) => <span className={`badge badge-${v === 'active' ? 'running' : 'queued'}`}>{v}</span> },
  { key: 'actions', label: '',
    render: (_, row) => (
      <button className="btn-danger btn-sm" onClick={() => handleDelete(row.id)}>Delete</button>
    )},
]
```

Replace the `<table>` block in the return JSX with:
```jsx
<DataTable
  columns={COLUMNS}
  data={targets}
  searchable
  loading={loading}
  emptyMessage="No targets yet"
  emptyAction={<button className="btn-primary" onClick={() => setAddOpen(true)}>Add your first target</button>}
/>
```

### Results page

- [ ] **Step 2: Update src/pages/Results.jsx**

```jsx
import { DataTable } from '../components/ui/DataTable'

const COLUMNS = [
  { key: 'title',    label: 'Finding',  sortable: true },
  { key: 'severity', label: 'Severity', sortable: true,
    render: (v) => <span className={`badge badge-${v}`}>{v}</span> },
  { key: 'target',   label: 'Target',   sortable: true },
  { key: 'status',   label: 'Status',   sortable: true },
  { key: 'created_at', label: 'Found',  sortable: true,
    render: (v) => v ? new Date(v).toLocaleDateString() : '—' },
]
```

Replace the table block with:
```jsx
<DataTable
  columns={COLUMNS}
  data={vulns}
  searchable
  loading={loading}
  emptyMessage="No findings yet"
  emptyAction={<p className="empty-sub">Run a scan to discover vulnerabilities</p>}
/>
```

### BountyHunter, AIModels history tab, Reports — follow the same pattern

For **BountyHunter** findings:
```jsx
const COLUMNS = [
  { key: 'title',    label: 'Finding',  sortable: true },
  { key: 'severity', label: 'Severity', sortable: true,
    render: (v) => <span className={`badge badge-${v}`}>{v}</span> },
  { key: 'target',   label: 'Target',   sortable: true },
  { key: 'bounty',   label: 'Bounty',   sortable: true },
]
```

For **AIModels** history:
```jsx
const COLUMNS = [
  { key: 'model',     label: 'Model',    sortable: true },
  { key: 'task_type', label: 'Task',     sortable: true },
  { key: 'tokens',    label: 'Tokens',   sortable: true },
  { key: 'cost_usd',  label: 'Cost',     sortable: true,
    render: (v) => v != null ? `$${v.toFixed(4)}` : '—' },
  { key: 'created_at',label: 'Time',     sortable: true,
    render: (v) => v ? new Date(v).toLocaleTimeString() : '—' },
]
```

For **Reports**:
```jsx
const COLUMNS = [
  { key: 'title',      label: 'Report',   sortable: true },
  { key: 'format',     label: 'Format',   sortable: true },
  { key: 'created_at', label: 'Created',  sortable: true,
    render: (v) => v ? new Date(v).toLocaleDateString() : '—' },
  { key: 'actions',    label: '',
    render: (_, row) => <a href={row.url} className="btn-secondary btn-sm" download>Download</a> },
]
```

- [ ] **Step 3: Commit after all page updates**

```bash
git add src/pages/Targets.jsx src/pages/Results.jsx src/pages/BountyHunter.jsx src/pages/AIModels.jsx src/pages/Reports.jsx
git commit -m "feat(pages): adopt DataTable with sort/filter/pagination across list pages"
```

---

## Task 12: Form Validation (ScanLauncher + GodMode)

**Files:**
- Modify: `src/components/ScanLauncher.jsx`
- Modify: `src/pages/GodMode.jsx`

- [ ] **Step 1: Add validation to ScanLauncher**

Read `src/components/ScanLauncher.jsx`, then add validation state and error display.

Add a `validate` function before the submit handler:

```jsx
// In ScanLauncher.jsx, add before handleLaunch:
const [errors, setErrors] = useState({})

const validate = () => {
  const e = {}
  if (!target.trim()) e.target = 'Target domain is required'
  if (!selectedScanType) e.scanType = 'Select a scan type'
  return e
}

// Replace the existing handleLaunch:
const handleLaunch = async () => {
  const e = validate()
  if (Object.keys(e).length) { setErrors(e); return }
  setErrors({})
  // ... existing launch logic
}
```

In the JSX, after the target input:
```jsx
{errors.target && <p className="field-error">{errors.target}</p>}
```

Apply `input-error` class conditionally:
```jsx
<input
  className={`input ${errors.target ? 'input-error' : ''}`}
  value={target}
  onChange={e => { setTarget(e.target.value); if (errors.target) setErrors(p => ({...p, target: null})) }}
  placeholder="example.com"
/>
```

- [ ] **Step 2: Add validation to GodMode launch form**

Read `src/pages/GodMode.jsx`, then add validation to `handleLaunch`:

```jsx
// In GodMode.jsx, add before handleLaunch:
const [errors, setErrors] = useState({})

// Replace handleLaunch start:
const handleLaunch = async () => {
  const e = {}
  if (!target.trim()) e.target = 'Target domain is required'
  if (maxTime && (isNaN(maxTime) || maxTime < 1)) e.maxTime = 'Must be a positive number'
  if (Object.keys(e).length) { setErrors(e); return }
  setErrors({})
  // ... existing logic
}
```

In JSX after target input:
```jsx
<input
  className={`input ${errors.target ? 'input-error' : ''}`}
  value={target}
  onChange={e => { setTarget(e.target.value); setErrors(p => ({...p, target: null})) }}
  placeholder="example.com or IP"
/>
{errors.target && <p className="field-error">{errors.target}</p>}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/ScanLauncher.jsx src/pages/GodMode.jsx
git commit -m "feat(forms): inline validation on ScanLauncher and GodMode launch form"
```

---

## Task 13: AttackGraph Side Panel + Node Enhancements

**Files:**
- Modify: `src/pages/AttackGraph.jsx`

- [ ] **Step 1: Read AttackGraph.jsx to understand current structure**

```bash
cat src/pages/AttackGraph.jsx
```

- [ ] **Step 2: Add node detail side panel**

The existing page uses `react-force-graph-2d`. Add these changes:

```jsx
// Add to the state section in AttackGraph.jsx:
const [selectedNode, setSelectedNode] = useState(null)
const [criticalOnly, setCriticalOnly] = useState(false)
```

Update the ForceGraph2D component to add node click handler and dynamic node radius:

```jsx
<ForceGraph2D
  // ... existing props
  onNodeClick={(node) => setSelectedNode(node)}
  nodeVal={node => {
    const risk = node.risk_score || 1
    return Math.max(2, Math.min(8, risk * 2))
  }}
  linkColor={link => link.critical ? '#ef4444' : undefined}
  linkWidth={link => link.critical ? 2 : 1}
/>
```

Add the side panel JSX (render alongside the graph):
```jsx
{selectedNode && (
  <div className="absolute top-4 right-4 w-72 card p-4 flex flex-col gap-3 shadow-modal animate-fade-in">
    <div className="flex items-center justify-between">
      <h3 className="card-title">{selectedNode.label || selectedNode.id}</h3>
      <button className="btn-icon" onClick={() => setSelectedNode(null)}><X size={12} /></button>
    </div>
    <div className="flex flex-col gap-2 text-xs">
      <div className="flex justify-between">
        <span className="text-slate-500">Type</span>
        <span className="badge badge-info">{selectedNode.type || 'unknown'}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-slate-500">Risk Score</span>
        <span className="text-slate-200 font-medium">{selectedNode.risk_score ?? '—'}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-slate-500">Vulnerabilities</span>
        <span className="text-red-400 font-medium">{selectedNode.vuln_count ?? 0}</span>
      </div>
      {selectedNode.last_seen && (
        <div className="flex justify-between">
          <span className="text-slate-500">Last Seen</span>
          <span className="text-slate-400">{new Date(selectedNode.last_seen).toLocaleDateString()}</span>
        </div>
      )}
    </div>
  </div>
)}
```

Add the "Critical Paths Only" toggle in the toolbar:
```jsx
<label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
  <input
    type="checkbox"
    checked={criticalOnly}
    onChange={e => setCriticalOnly(e.target.checked)}
    className="rounded border-bg-border"
  />
  Critical paths only
</label>
```

Filter edges when criticalOnly is true:
```jsx
const displayEdges = criticalOnly
  ? attackGraph.edges.filter(e => e.critical)
  : attackGraph.edges
```

- [ ] **Step 3: Commit**

```bash
git add src/pages/AttackGraph.jsx
git commit -m "feat(attack-graph): node detail side panel, critical path filter, risk-based node sizing"
```

---

## Task 14: God Mode Mission Timeline

**Files:**
- Modify: `src/pages/GodMode.jsx`

- [ ] **Step 1: Replace mission pipeline badges with vertical timeline**

Read `src/pages/GodMode.jsx`. Find the mission pipeline section (renders missions as badges/cards) and replace with:

```jsx
{/* Mission Timeline */}
<div className="card">
  <div className="card-header">
    <span className="card-title">Mission Pipeline</span>
  </div>
  <div className="p-4 flex flex-col">
    {MISSIONS.map((m, i) => {
      const mData = session?.missions?.[m.id] || {}
      const status = mData.status || 'pending'
      const isRunning = status === 'running'
      const [expanded, setExpanded] = useLocalStorage(`gm-mission-${m.id}`, false)
      return (
        <div key={m.id} className="flex gap-3">
          {/* Timeline spine */}
          <div className="flex flex-col items-center">
            <div className={clsx(
              'w-7 h-7 rounded-full border-2 flex items-center justify-center flex-shrink-0 text-xs font-bold transition-all',
              status === 'complete' ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400' :
              isRunning ? 'border-cyan-400 bg-cyan-400/20 text-cyan-400 animate-pulse' :
              status === 'failed'  ? 'border-red-500 bg-red-500/10 text-red-400' :
              'border-bg-border bg-bg-elevated text-slate-600'
            )}>
              {status === 'complete' ? '✓' : i + 1}
            </div>
            {i < MISSIONS.length - 1 && (
              <div className={clsx('w-px flex-1 my-1 min-h-4', status === 'complete' ? 'bg-emerald-500/30' : 'bg-bg-border')} />
            )}
          </div>

          {/* Mission content */}
          <div className="flex-1 pb-4">
            <button
              className="w-full flex items-center justify-between gap-2 text-left"
              onClick={() => setExpanded(!expanded)}
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-200">{m.label}</span>
                <span className={`badge badge-${status === 'complete' ? 'completed' : isRunning ? 'running' : status === 'failed' ? 'failed' : 'queued'}`}>
                  {status}
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-500">
                {mData.findings_count != null && (
                  <span>{mData.findings_count} findings</span>
                )}
                {mData.duration_s != null && (
                  <span>{mData.duration_s.toFixed(0)}s</span>
                )}
                <ChevronRight size={12} className={clsx('transition-transform', expanded && 'rotate-90')} />
              </div>
            </button>

            {/* Log preview (last 3 lines collapsed, full log expanded) */}
            {expanded && mData.logs && mData.logs.length > 0 && (
              <div className="mt-2 terminal text-xs max-h-40">
                {mData.logs.map((line, li) => (
                  <div key={li} className={logLevelColor(line)}>{line}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      )
    })}
  </div>
</div>
```

Note: `MISSIONS` is the existing array of mission definitions already in GodMode.jsx. `logLevelColor` is the existing helper function. `useLocalStorage` is imported from `'../hooks/useLocalStorage'`.

- [ ] **Step 2: Commit**

```bash
git add src/pages/GodMode.jsx
git commit -m "feat(god-mode): vertical mission timeline with expandable per-mission logs"
```

---

## Task 15: Swarm Agent Grid + Confidence Scores

**Files:**
- Modify: `src/pages/SwarmIntelligence.jsx`

- [ ] **Step 1: Read SwarmIntelligence.jsx**

```bash
cat src/pages/SwarmIntelligence.jsx
```

- [ ] **Step 2: Add the 8-agent real-time grid**

Add agent grid state and the polling useEffect:

```jsx
// Add to state in SwarmIntelligence.jsx:
const [agentGrid, setAgentGrid] = useState({})

// Add to the data-fetch useEffect or create a new one:
useEffect(() => {
  const refresh = async () => {
    try {
      const r = await endpoints.swarmIntelAgents()
      // Build a map keyed by agent type
      const map = {}
      ;(r.data || []).forEach(a => { map[a.type || a.name] = a })
      setAgentGrid(map)
    } catch {}
  }
  refresh()
  const t = setInterval(refresh, 4000)
  return () => clearInterval(t)
}, [])
```

Add the agent grid JSX (add as a new section above or below the existing content):

```jsx
{/* Real-Time Agent Grid */}
<div>
  <div className="section-header">
    <div>
      <h2 className="section-title">Agent Status</h2>
      <p className="section-sub">Live activity across all specialized agents</p>
    </div>
  </div>
  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
    {['xss', 'sqli', 'ssrf', 'idor', 'auth', 'biz_logic', 'mobile', 'api'].map(type => {
      const agent = agentGrid[type] || {}
      const status = agent.status || 'idle'
      const confidence = agent.confidence ?? null
      return (
        <div key={type} className="card p-4 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-300 uppercase">{type}</span>
            <span className={clsx(
              'status-dot',
              status === 'running' ? 'status-dot-pulse' :
              status === 'done'    ? 'status-dot-online' :
              status === 'error'   ? 'status-dot-error' :
              'status-dot-idle'
            )} />
          </div>
          <div className="text-[10px] text-slate-500 truncate">
            {agent.last_target || 'No target'}
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              {agent.findings_count ?? 0} findings
            </span>
            {confidence != null && (
              <span className={clsx(
                'badge text-[10px]',
                confidence >= 80 ? 'badge-completed' :
                confidence >= 50 ? 'badge-medium' :
                'badge-failed'
              )}>
                {confidence}%
              </span>
            )}
          </div>
        </div>
      )
    })}
  </div>
</div>
```

- [ ] **Step 3: Commit**

```bash
git add src/pages/SwarmIntelligence.jsx
git commit -m "feat(swarm): real-time 8-agent grid with status dots and confidence score badges"
```

---

## Task 16: Adaptive Recon "Why" Panel

**Files:**
- Modify: `src/pages/Research.jsx`
- Modify: `src/pages/GodMode.jsx`

- [ ] **Step 1: Create a shared WhyPanel component inline in Research.jsx**

Add this component and usage to `src/pages/Research.jsx`:

```jsx
// Add to imports in Research.jsx:
import { useLocalStorage } from '../hooks/useLocalStorage'
import { ChevronDown, ChevronUp, Brain } from 'lucide-react'

// Add WhyPanel component (above the page component):
function WhyPanel({ target }) {
  const [open, setOpen] = useLocalStorage('why-panel-open', false)
  const [priorities, setPriorities] = useState([])

  useEffect(() => {
    if (!target) return
    endpoints.brainPriorities(5)
      .then(r => setPriorities(r.data || []))
      .catch(() => {})
  }, [target])

  if (!target || priorities.length === 0) return null

  return (
    <div className="card">
      <button
        className="card-header w-full cursor-pointer hover:bg-white/[0.02] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <span className="card-title">
          <Brain size={14} className="text-accent-secondary" />
          Adaptive Recon Intelligence
        </span>
        {open ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
      </button>
      {open && (
        <div className="card-body flex flex-col gap-2">
          {priorities.map((p, i) => (
            <div key={i} className="flex items-start gap-3 text-xs py-2 border-b border-bg-border last:border-0">
              <span className="text-accent-primary font-bold font-mono w-4 flex-shrink-0">#{i + 1}</span>
              <div className="flex-1">
                <p className="text-slate-200 font-medium">{p.target || p.label}</p>
                {p.reasons && (
                  <ul className="mt-1 flex flex-col gap-0.5">
                    {p.reasons.map((r, j) => (
                      <li key={j} className="text-slate-500">· {r}</li>
                    ))}
                  </ul>
                )}
              </div>
              {p.score != null && (
                <span className="text-slate-400 font-mono">{p.score.toFixed(2)}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

Add `<WhyPanel target={selectedMode?.target || ''} />` at the top of the page's return JSX (before the mode selector).

- [ ] **Step 2: Add WhyPanel to GodMode.jsx**

Read `src/pages/GodMode.jsx`, add the same `WhyPanel` component (copy the same code) and render it above the session section when a target is set:

```jsx
// In GodMode.jsx return, add near the top of the page content:
<WhyPanel target={target} />
```

- [ ] **Step 3: Commit**

```bash
git add src/pages/Research.jsx src/pages/GodMode.jsx
git commit -m "feat(intelligence): adaptive recon Why panel on Research and GodMode pages"
```

---

## Task 17: Final Integration Check

- [ ] **Step 1: Run all tests**

```bash
cd /path/to/oneinfinity/web/frontend
npm test
```

Expected: all tests pass.

- [ ] **Step 2: Run production build**

```bash
npm run build 2>&1 | tail -10
```

Expected: `✓ built in` with no errors and no `[WARN]` about missing modules.

- [ ] **Step 3: Manual smoke test checklist**

Start the dev server: `npm run dev`

Open `http://localhost:3000` and verify:

- [ ] Dark mode loads by default
- [ ] Theme toggle (sun/moon icon in header) switches to light mode without reload
- [ ] Light mode has readable contrast (dark text on light background)
- [ ] Refreshing the page restores the selected theme
- [ ] `Cmd+K` (or `Ctrl+K`) opens the command palette
- [ ] Typing in the palette filters routes in real-time
- [ ] Arrow keys navigate results; Enter navigates to the page
- [ ] Breadcrumbs appear on all pages except `/dashboard`
- [ ] Resizing the browser window below 768px shows a hamburger menu
- [ ] Hamburger opens a mobile drawer sidebar; backdrop click closes it
- [ ] Sidebar open/closed state persists on page refresh
- [ ] Console open/closed state persists on page refresh
- [ ] `/results` page shows skeleton loaders briefly, then populates or shows empty state
- [ ] `/targets` table is sortable by clicking column headers
- [ ] Search input on `/targets` filters rows client-side
- [ ] Pagination controls appear when there are more than 25 rows
- [ ] Trying to launch a scan without filling in the target field shows a red validation error
- [ ] API error toasts appear in the top-right when backend is unavailable (stop the backend and navigate)
- [ ] Status bar shows "API Offline" in red when the backend is down
- [ ] `/attack-graph` — clicking a node opens the side detail panel
- [ ] `/attack-graph` — "Critical paths only" toggle hides non-critical edges
- [ ] `/god-mode` — clicking a mission row in the timeline expands its logs inline
- [ ] `/swarm` — 8 agent cards grid is visible with status dots
- [ ] `/research` — "Adaptive Recon Intelligence" collapsible panel appears when a target is selected

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: Phase 1-4 OneInfinity SaaS platform transformation complete"
```

---

## Success Criteria Checklist

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
