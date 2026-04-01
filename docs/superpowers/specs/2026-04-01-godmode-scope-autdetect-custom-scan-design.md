# GOD MODE — Scope Auto-Detection & Custom Scan Design

**Date:** 2026-04-01
**Status:** Approved
**Scope:** `web/frontend/src/pages/GodMode.jsx`, `web/backend/main.py`

---

## Overview

Two connected features for the GOD MODE launch form:

1. **URL Auto-Detection** — when the user types a target URL, the system detects the target type and silently switches to the best-fit preset, updating module badges automatically.
2. **Custom Preset** — a 5th scan preset that expands the Modules section into interactive rows, letting the user choose exactly which modules to run and at what intensity.

---

## Feature 1: URL Auto-Detection

### Behaviour

On every `onChange` of the target input (debounced 400ms), the URL is inspected and the best-fit preset is selected automatically. A cyan detection badge appears below the input confirming what was detected.

Detection only fires when:
- The URL is non-empty
- It contains a `.` (looks like a real domain)
- The user has **not** manually picked a preset since the last URL change

A `userPickedPreset` boolean flag tracks manual preset selection. Clicking a preset card sets `userPickedPreset = true`. Changing the target input resets it to `false`, re-enabling auto-detection.

### Detection Rules

| URL pattern (case-insensitive) | Detected type | Auto-switches to preset |
|---|---|---|
| ends with `.apk` or `.ipa` | mobile | Quick |
| contains `/api/`, `/graphql`, starts with `api.`, `graphql.` | api | Standard |
| contains `chat`, `llm`, `gpt`, `bot`, or starts with `ai.` | ai | Standard |
| anything else | web | Deep |

### UI

- Target input gets a subtle cyan border glow when detection fires
- Badge below input: `🔵 Detected: API target — switched to Standard`
- Badge disappears when input is cleared
- No badge shown when `userPickedPreset` is true (user is in manual control)

### New State

```js
const [detectedType, setDetectedType] = useState(null)   // 'web' | 'api' | 'mobile' | 'ai' | null
const [userPickedPreset, setUserPickedPreset] = useState(false)
```

---

## Feature 2: Custom Preset

### Preset Definition

A 5th entry added to the `PRESETS` array in `GodMode.jsx`:

```js
{
  id: 'custom',
  label: 'Custom',
  desc: 'Pick modules + intensity yourself',
  color: 'border-violet-500/40 bg-violet-500/10 text-violet-300',
  activeColor: 'border-violet-400 bg-violet-500/20 text-violet-200',
  no_swarm: false,   // derived at launch time from selected modules
  no_research: false, // derived at launch time from selected modules
  modules: [],       // dynamic — driven by customModules state
}
```

The Custom card spans the full 2-column width in the preset grid.

### Module Configuration State

```js
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

State persists across preset switches — switching away from Custom and back restores the user's previous configuration.

### Module Row UI (Custom mode only)

When Custom preset is active, the Modules section renders interactive rows instead of static badges. Each row contains:

- **Checkbox** — toggles `enabled` for that module
- **Module name** (bold) + description (muted, truncated)
- **Intensity dropdown** (`Low / Medium / High / Aggressive`) — disabled and grayed out when module is unchecked

Intensity dropdown border/text color reflects the selected level:
- Low → blue
- Medium → cyan
- High → orange
- Aggressive → red

### Custom Preset Card Summary Tag

The Custom preset card displays a live summary tag showing how many modules are enabled and whether intensities are mixed:

- `3 modules · Medium` — all enabled modules at the same intensity
- `3 modules · Mixed intensity` — enabled modules at different intensities

### Module Rows for Non-Custom Presets

When any non-custom preset is active, the Modules section renders static read-only badges (existing behaviour), unchanged.

---

## Feature 3: Backend Changes

### Request Payload

`POST /api/god-mode/run` accepts two new optional fields:

```json
{
  "modules": ["recon", "vuln_scan", "auth"],
  "intensities": { "recon": "high", "vuln_scan": "medium", "auth": "low" }
}
```

Both fields are optional. If absent (non-custom presets), existing behaviour is unchanged.

### `no_swarm` / `no_research` Derivation (Custom)

When `modules` is non-empty (Custom preset), the flags are derived server-side:

```python
if modules:
    no_swarm    = 'active_testing' not in modules
    no_research = 'ai_hypothesis'  not in modules
```

This keeps the existing engine logic working without any engine changes.

### Storage

`modules` and `intensities` are stored in the scan record alongside existing fields. They are passed through to `GodModeConductor.run()` as extra kwargs and ignored by the engine for now. This is forward-compatible: future engine work can read them to adjust tool selection and depth.

---

## File Scope

| File | Changes |
|---|---|
| `web/frontend/src/pages/GodMode.jsx` | Add `detectedType`, `userPickedPreset`, `customModules` state; add detection logic; add Custom to PRESETS; conditional module row rendering; updated launch payload |
| `web/backend/main.py` | Accept `modules` + `intensities` in god mode run endpoint; derive `no_swarm`/`no_research` when modules list is present |

No other files require changes.

---

## Out of Scope

- Engine enforcement of intensity levels (future work)
- Saving/loading named custom configurations
- Per-module advanced settings beyond intensity
- AI/LLM module (marked `comingSoon`, remains disabled)
