# GOD MODE Scope Auto-Detection & Custom Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add URL-based target type auto-detection that silently switches scan presets, and a Custom preset that lets users pick which modules to run with per-module intensity levels.

**Architecture:** All frontend changes are contained to `GodMode.jsx` — new state variables, a `detectTargetType` helper, conditional rendering in the Modules section, and updated launch payload. Backend change is a small addition to the god mode run endpoint: read `modules` and `intensities` from the request and store them in the scan record.

**Tech Stack:** React 18, Vite, Tailwind CSS, FastAPI

**Spec:** `docs/superpowers/specs/2026-04-01-godmode-scope-autdetect-custom-scan-design.md`

---

## File Map

| File | What changes |
|---|---|
| `web/frontend/src/pages/GodMode.jsx` | New state, detection logic, Custom preset, module row UI, updated payload |
| `web/backend/main.py` | Accept + store `modules`/`intensities`, derive `no_swarm`/`no_research` from modules |

No other files require changes.

---

## Task 1: Backend — accept modules and intensities

**Files:**
- Modify: `web/backend/main.py` (god mode run endpoint, ~line 2307)

- [ ] **Step 1: Add modules and intensities parsing after existing field parsing**

In `web/backend/main.py`, inside `async def god_mode_run`, after line `report_fmt = str(data.get("report_fmt", "markdown"))` (currently ~line 2318), add:

```python
    modules      = data.get("modules") or []        # list[str], empty = preset defaults
    intensities  = data.get("intensities") or {}    # dict[str,str]

    # When a custom module list is provided, derive flags from it
    if modules:
        no_swarm    = 'active_testing' not in modules
        no_research = 'ai_hypothesis'  not in modules
```

- [ ] **Step 2: Store modules and intensities in the scan record**

In the same function, update `_gm_scan_entry` dict to include the new fields. Find this block (~line 2332):

```python
    _gm_scan_entry = {
        "id": gm_scan_id, "target": target, "scan_type": "god_mode",
        "profile": "god_mode", "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None, "progress": 0, "findings_count": 0,
        "log_lines": [], "pid": None, "phase": "starting",
    }
```

Replace with:

```python
    _gm_scan_entry = {
        "id": gm_scan_id, "target": target, "scan_type": "god_mode",
        "profile": "custom" if modules else "god_mode", "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None, "progress": 0, "findings_count": 0,
        "log_lines": [], "pid": None, "phase": "starting",
        "modules": modules, "intensities": intensities,
    }
```

- [ ] **Step 3: Verify with curl**

Restart the backend:
```bash
cd /home/devendra-yadav/oneinfinity/web/backend && fuser -k 8000/tcp 2>/dev/null; python3 main.py &>/tmp/backend.log &
sleep 4 && curl -s http://localhost:8000/health
```
Expected: `{"status":"ok"}`

Test the new fields are accepted without error:
```bash
curl -s -X POST http://localhost:8000/api/god-mode/run \
  -H "Content-Type: application/json" \
  -d '{"target":"test.example.com","modules":["recon","vuln_scan"],"intensities":{"recon":"high","vuln_scan":"medium"}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('scan_id:', d.get('scan_id')); print('ok' if 'scan_id' in d else 'FAIL')"
```
Expected output contains `scan_id: gm-` and `ok`.

Verify scan record has modules stored:
```bash
curl -s http://localhost:8000/api/god-mode/sessions \
  | python3 -c "import sys,json; d=json.load(sys.stdin); s=d.get('sessions',[]); print('modules in record:', s[0].get('modules') if s else 'no sessions yet')"
```

- [ ] **Step 4: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/backend/main.py
git commit -m "feat(backend): accept modules and intensities in god-mode run endpoint"
```

---

## Task 2: Frontend — add Custom preset and new state variables

**Files:**
- Modify: `web/frontend/src/pages/GodMode.jsx`

- [ ] **Step 1: Add Custom to the PRESETS array**

In `GodMode.jsx`, find the `PRESETS` array (currently ends at the `stealth` entry ~line 95). Add the Custom entry after stealth:

```js
  {
    id: 'custom',
    label: 'Custom',
    desc: 'Pick modules + intensity yourself',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-300',
    activeColor: 'border-violet-400 bg-violet-500/20 text-violet-200',
    no_swarm: false,
    no_research: false,
    modules: [],
  },
```

- [ ] **Step 2: Add new state variables inside the GodMode component**

In `GodMode.jsx`, after the existing `const [authValue, setAuthValue] = useState('')` line (~line 131), add:

```js
  // Auto-detection state
  const [detectedType, setDetectedType]       = useState(null)   // 'web'|'api'|'mobile'|'ai'|null
  const [userPickedPreset, setUserPickedPreset] = useState(false)

  // Custom preset module configuration
  const [customModules, setCustomModules] = useState({
    recon:          { enabled: true,  intensity: 'medium' },
    vuln_scan:      { enabled: true,  intensity: 'medium' },
    active_testing: { enabled: false, intensity: 'medium' },
    auth:           { enabled: true,  intensity: 'medium' },
    business_logic: { enabled: false, intensity: 'medium' },
    chains:         { enabled: false, intensity: 'medium' },
    ai_hypothesis:  { enabled: false, intensity: 'medium' },
  })
```

- [ ] **Step 3: Update preset click handler to set userPickedPreset**

Find the preset button `onClick` inside the Scope section (~line 361):
```js
onClick={() => setPreset(p.id)}
```

Replace with:
```js
onClick={() => { setPreset(p.id); setUserPickedPreset(true) }}
```

- [ ] **Step 4: Verify the Custom card renders**

Run the frontend dev server if not running:
```bash
cd /home/devendra-yadav/oneinfinity/web/frontend && npm run dev &>/tmp/frontend.log &
```
Open `http://localhost:5173` (or wherever it runs). Go to the Scan page. Confirm a 5th "Custom" card appears in the Scope grid spanning the full width.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/frontend/src/pages/GodMode.jsx
git commit -m "feat(ui): add Custom preset card and state to GOD MODE"
```

---

## Task 3: Frontend — URL auto-detection logic

**Files:**
- Modify: `web/frontend/src/pages/GodMode.jsx`

- [ ] **Step 1: Add the detectTargetType helper function**

In `GodMode.jsx`, after the `formatDuration` function (~line 116) and before the `GodMode` component, add:

```js
function detectTargetType(url) {
  if (!url || !url.includes('.')) return null
  const u = url.toLowerCase()
  if (u.endsWith('.apk') || u.endsWith('.ipa')) return 'mobile'
  if (u.includes('/api/') || u.includes('/graphql') ||
      u.match(/^https?:\/\/api\./) || u.match(/^https?:\/\/graphql\./)) return 'api'
  if (/chat|llm|gpt|bot/.test(u) || u.match(/^https?:\/\/ai\./)) return 'ai'
  return 'web'
}

const TYPE_TO_PRESET = {
  mobile: 'quick',
  api:    'standard',
  ai:     'standard',
  web:    'deep',
}
```

- [ ] **Step 2: Add the debounced detection effect**

In `GodMode.jsx`, after the existing `useEffect` blocks and before `// ── Launch`, add:

```js
  // URL auto-detection — runs 400ms after target changes
  useEffect(() => {
    if (!target.trim() || userPickedPreset) {
      if (!target.trim()) setDetectedType(null)
      return
    }
    const timer = setTimeout(() => {
      const type = detectTargetType(target.trim())
      if (type) {
        setDetectedType(type)
        setPreset(TYPE_TO_PRESET[type])
      }
    }, 400)
    return () => clearTimeout(timer)
  }, [target, userPickedPreset])
```

- [ ] **Step 3: Add detection badge below the target input**

In `GodMode.jsx`, find the target input block:
```jsx
              <div>
                <label className="label">Target</label>
                <input
                  className="input"
                  placeholder="https://target.com"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && !isRunning && !launching && target.trim() && handleLaunch()}
                />
              </div>
```

Replace with:
```jsx
              <div>
                <label className="label">Target</label>
                <input
                  className={clsx('input', detectedType && !userPickedPreset && 'border-cyan-500/40 shadow-[0_0_0_2px_rgba(0,217,255,0.08)]')}
                  placeholder="https://target.com"
                  value={target}
                  onChange={e => { setTarget(e.target.value); setUserPickedPreset(false) }}
                  onKeyDown={e => e.key === 'Enter' && !isRunning && !launching && target.trim() && handleLaunch()}
                />
                {detectedType && !userPickedPreset && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-[10px] text-cyan-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse flex-shrink-0" />
                    Detected: {detectedType.toUpperCase()} target — switched to {TYPE_TO_PRESET[detectedType]}
                  </div>
                )}
              </div>
```

- [ ] **Step 4: Verify detection works**

In the browser on the Scan page:
1. Type `https://api.example.com/graphql` — expect cyan border on input, badge "Detected: API target — switched to standard", Standard preset highlighted
2. Type `https://example.apk` — expect badge "Detected: MOBILE target — switched to quick", Quick preset highlighted
3. Click Deep preset manually — expect badge disappears (userPickedPreset = true), preset stays on Deep
4. Clear the input and retype — expect detection fires again

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/frontend/src/pages/GodMode.jsx
git commit -m "feat(ui): add URL target-type auto-detection to GOD MODE scan form"
```

---

## Task 4: Frontend — Custom preset module rows UI

**Files:**
- Modify: `web/frontend/src/pages/GodMode.jsx`

- [ ] **Step 1: Add intensity colour helper**

In `GodMode.jsx`, after `TYPE_TO_PRESET` add:

```js
const INTENSITY_COLORS = {
  low:        'border-blue-500/40 text-blue-300',
  medium:     'border-cyan-500/40 text-cyan-300',
  high:       'border-orange-500/40 text-orange-300',
  aggressive: 'border-red-500/40 text-red-300',
}
```

- [ ] **Step 2: Replace the static Modules section with conditional rendering**

Find the current Modules section in `GodMode.jsx` (the `<div>` with `<label className="label">Modules</label>`, ~line 375):

```jsx
              {/* Module badges — shows what the selected preset runs */}
              <div>
                <label className="label">Modules</label>
                <div className="flex flex-wrap gap-1.5">
                  {ALL_MODULES.map(m => {
                    const included = activePreset.modules.includes(m.id)
                    return (
                      <div
                        key={m.id}
                        title={m.desc}
                        className={clsx(
                          'flex items-center gap-1 px-2 py-1 rounded-lg border text-[10px] font-medium transition-all',
                          m.comingSoon
                            ? 'border-slate-700 text-slate-600 bg-transparent'
                            : included
                            ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                            : 'border-slate-700 text-slate-600 bg-transparent line-through'
                        )}
                      >
                        <m.icon size={9} />
                        {m.label}
                        {m.comingSoon && <span className="text-[8px] text-slate-600 ml-0.5">soon</span>}
                      </div>
                    )
                  })}
                </div>
              </div>
```

Replace with:

```jsx
              {/* Modules — badges for presets, interactive rows for Custom */}
              <div>
                <label className="label">
                  Modules
                  {preset === 'custom' && (
                    <span className="ml-2 text-[9px] text-slate-500 normal-case tracking-normal">
                      check to enable · set intensity per module
                    </span>
                  )}
                </label>

                {preset !== 'custom' ? (
                  <div className="flex flex-wrap gap-1.5">
                    {ALL_MODULES.map(m => {
                      const included = activePreset.modules.includes(m.id)
                      return (
                        <div
                          key={m.id}
                          title={m.desc}
                          className={clsx(
                            'flex items-center gap-1 px-2 py-1 rounded-lg border text-[10px] font-medium transition-all',
                            m.comingSoon
                              ? 'border-slate-700 text-slate-600 bg-transparent'
                              : included
                              ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                              : 'border-slate-700 text-slate-600 bg-transparent line-through'
                          )}
                        >
                          <m.icon size={9} />
                          {m.label}
                          {m.comingSoon && <span className="text-[8px] text-slate-600 ml-0.5">soon</span>}
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="flex flex-col gap-1.5">
                    {ALL_MODULES.filter(m => !m.comingSoon).map(m => {
                      const cfg = customModules[m.id]
                      const enabled = cfg?.enabled ?? false
                      const intensity = cfg?.intensity ?? 'medium'
                      return (
                        <div
                          key={m.id}
                          className={clsx(
                            'flex items-center gap-2.5 px-3 py-2 rounded-lg border transition-all',
                            enabled
                              ? 'border-cyan-500/20 bg-cyan-500/4'
                              : 'border-bg-border bg-bg-secondary opacity-50'
                          )}
                        >
                          {/* Checkbox */}
                          <button
                            onClick={() => setCustomModules(prev => ({
                              ...prev,
                              [m.id]: { ...prev[m.id], enabled: !enabled }
                            }))}
                            className={clsx(
                              'w-4 h-4 rounded flex-shrink-0 flex items-center justify-center border transition-all',
                              enabled
                                ? 'bg-cyan-400 border-cyan-400 text-black'
                                : 'border-slate-600 bg-transparent'
                            )}
                          >
                            {enabled && <span className="text-[9px] font-black leading-none">✓</span>}
                          </button>

                          {/* Info */}
                          <div className="flex-1 min-w-0">
                            <div className="text-[11px] font-semibold text-slate-200">{m.label}</div>
                            <div className="text-[9px] text-slate-500 truncate">{m.desc}</div>
                          </div>

                          {/* Intensity */}
                          <select
                            disabled={!enabled}
                            value={intensity}
                            onChange={e => setCustomModules(prev => ({
                              ...prev,
                              [m.id]: { ...prev[m.id], intensity: e.target.value }
                            }))}
                            className={clsx(
                              'text-[10px] bg-bg-elevated border rounded-md px-1.5 py-1 flex-shrink-0 transition-all',
                              enabled
                                ? INTENSITY_COLORS[intensity]
                                : 'border-slate-700 text-slate-600'
                            )}
                          >
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="aggressive">Aggressive</option>
                          </select>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
```

- [ ] **Step 3: Add live summary tag to the Custom preset card**

Find the Custom preset card render. The preset cards are rendered by `PRESETS.map(p => ...)` (~line 359). The map currently renders:

```jsx
                    <button
                      key={p.id}
                      onClick={() => { setPreset(p.id); setUserPickedPreset(true) }}
                      className={clsx(
                        'flex flex-col items-start gap-0.5 p-3 rounded-xl border text-left transition-all',
                        preset === p.id ? p.activeColor : p.color + ' opacity-70 hover:opacity-100'
                      )}
                    >
                      <span className="text-xs font-semibold">{p.label}</span>
                      <span className="text-[10px] opacity-70 leading-tight">{p.desc}</span>
                    </button>
```

Replace with:

```jsx
                    <button
                      key={p.id}
                      onClick={() => { setPreset(p.id); setUserPickedPreset(true) }}
                      className={clsx(
                        'flex flex-col items-start gap-0.5 p-3 rounded-xl border text-left transition-all',
                        p.id === 'custom' && 'col-span-2',
                        preset === p.id ? p.activeColor : p.color + ' opacity-70 hover:opacity-100'
                      )}
                    >
                      <div className="flex items-center gap-2 w-full">
                        <span className="text-xs font-semibold">{p.label}</span>
                        {p.id === 'custom' && preset === 'custom' && (() => {
                          const enabled = Object.values(customModules).filter(c => c.enabled)
                          const intensities = [...new Set(enabled.map(c => c.intensity))]
                          const summary = enabled.length === 0
                            ? 'no modules selected'
                            : `${enabled.length} module${enabled.length > 1 ? 's' : ''} · ${intensities.length > 1 ? 'Mixed intensity' : (intensities[0] ?? 'medium')}`
                          return (
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-violet-500/20 border border-violet-500/30 text-violet-300">
                              {summary}
                            </span>
                          )
                        })()}
                      </div>
                      <span className="text-[10px] opacity-70 leading-tight">{p.desc}</span>
                    </button>
```

- [ ] **Step 4: Verify Custom mode UI in browser**

1. Click the Custom preset card — confirm module rows appear with checkboxes and intensity dropdowns
2. Toggle a checkbox off — confirm row dims and intensity select grays out
3. Change an intensity — confirm dropdown border/text color changes
4. Check the Custom card shows the summary tag (e.g. "3 modules · medium")
5. Switch to Deep preset — confirm static badges return, customModules state is preserved
6. Switch back to Custom — confirm previous checkboxes are still set

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/frontend/src/pages/GodMode.jsx
git commit -m "feat(ui): add Custom preset module configurator with per-module intensity"
```

---

## Task 5: Frontend — wire custom modules into launch payload

**Files:**
- Modify: `web/frontend/src/pages/GodMode.jsx`

- [ ] **Step 1: Update handleLaunch to send modules and intensities when Custom is active**

Find `handleLaunch` in `GodMode.jsx`. Currently the `endpoints.godModeRun` call is:

```js
      await endpoints.godModeRun({
        target:       target.trim(),
        max_time:     '0',
        max_findings: 0,
        no_swarm:     activePreset.no_swarm,
        no_research:  activePreset.no_research,
        report_fmt:   reportFmt,
        ...authPayload,
      })
```

Replace with:

```js
      const isCustom = preset === 'custom'
      const enabledModules = isCustom
        ? Object.entries(customModules).filter(([, c]) => c.enabled).map(([id]) => id)
        : []
      const moduleIntensities = isCustom
        ? Object.fromEntries(
            Object.entries(customModules)
              .filter(([, c]) => c.enabled)
              .map(([id, c]) => [id, c.intensity])
          )
        : {}

      await endpoints.godModeRun({
        target:       target.trim(),
        max_time:     '0',
        max_findings: 0,
        no_swarm:     activePreset.no_swarm,
        no_research:  activePreset.no_research,
        report_fmt:   reportFmt,
        ...(isCustom && enabledModules.length > 0 && {
          modules:     enabledModules,
          intensities: moduleIntensities,
        }),
        ...authPayload,
      })
```

- [ ] **Step 2: Update the launch notification to reflect custom config**

Find the notification line in `handleLaunch`:
```js
      addNotification(`GOD MODE launched (${activePreset.label}) — Foundation starting`, 'success')
```

Replace with:
```js
      const launchLabel = isCustom
        ? `Custom (${enabledModules.length} modules)`
        : activePreset.label
      addNotification(`GOD MODE launched (${launchLabel}) — Foundation starting`, 'success')
```

- [ ] **Step 3: Guard against launching Custom with zero modules**

In `handleLaunch`, after `if (!target.trim()) return`, add:

```js
    if (preset === 'custom') {
      const hasAny = Object.values(customModules).some(c => c.enabled)
      if (!hasAny) {
        addNotification('Select at least one module before launching', 'warn')
        return
      }
    }
```

- [ ] **Step 4: Verify end-to-end in browser**

1. Select Custom preset, enable only Recon (High) and Vuln Scan (Medium)
2. Click Launch GOD MODE on a test target
3. Check browser network tab → request body should contain `"modules":["recon","vuln_scan"],"intensities":{"recon":"high","vuln_scan":"medium"}`
4. Check success notification shows "Custom (2 modules)"
5. Try launching Custom with all modules unchecked — confirm warn notification fires and launch is blocked

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/frontend/src/pages/GodMode.jsx
git commit -m "feat(ui): wire custom module selection and intensities into god-mode launch payload"
```

---

## Self-Review Notes

- All PRESETS entries now require `col-span-2` for Custom card — handled via `p.id === 'custom' && 'col-span-2'` in the className
- `TYPE_TO_PRESET` and `INTENSITY_COLORS` are defined outside the component (no re-creation on render)
- `customModules` state key names exactly match `ALL_MODULES[].id` values — consistent throughout
- Backend derives `no_swarm`/`no_research` from `modules` only when `modules` is non-empty, leaving existing presets unchanged
- Zero-module guard prevents a confusing empty scan
- `col-span-2` on the Custom card requires the parent grid to be `grid-cols-2` — confirmed it is at `GodMode.jsx:358`
