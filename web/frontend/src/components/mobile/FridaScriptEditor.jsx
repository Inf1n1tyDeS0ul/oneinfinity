/**
 * Frida Script Lab — Phase 3
 *
 * Enhanced from the original editor to support:
 *  - Companion device mode (deviceId from Phase 0) alongside APK-pipeline mode
 *  - Full script library from FridaScriptGenerator (6 scripts per category)
 *  - Live output streaming via WebSocket session event messages
 *  - MASTG test mapping badges on every finding
 *  - frida-server status indicator with push button
 *  - AI hook generation from package name
 *  - MASTG coverage report generation
 *  - Phase 2 attack bridge status (tokens captured → attacks launched)
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Terminal, Play, Save, Loader, CheckCircle, XCircle, Code, Zap, Shield,
         RefreshCw, ChevronDown, ChevronRight, Lock, Cpu, Database, Wifi, Activity } from 'lucide-react';
import api from '../../utils/api';

const safeArray = (v) => (Array.isArray(v) ? v : []);

// Severity helpers
const SEV_COLOR = { critical: '#ff2244', high: '#ff6600', medium: '#ffaa00', low: '#44aaff', info: '#888' };
const SEV_BG    = { critical: '#330011', high: '#331100', medium: '#332200', low: '#001133', info: '#111' };

// Category icons
const CAT_ICON = { ssl: <Lock size={11} />, root: <Shield size={11} />, crypto: <Cpu size={11} />,
                   storage: <Database size={11} />, network: <Wifi size={11} />, auth: <Activity size={11} /> };

// Built-in minimal templates for backward compat (APK pipeline mode)
const TEMPLATE_SCRIPTS = {
  ssl_bypass:        { name: 'SSL Pinning Bypass', description: 'Universal SSL certificate validation bypass (6 layers)', mastg: ['MASTG-TEST-0022','MASTG-TEST-0242'] },
  root_bypass:       { name: 'Root Detection Bypass', description: 'Bypass RootBeer, SafetyNet, su paths (6 layers)', mastg: ['MASTG-TEST-0045'] },
  anti_debug_bypass: { name: 'Anti-Debug Bypass', description: 'Bypass ptrace, debugger checks, ANDROID_ID fingerprinting', mastg: ['MASTG-TEST-0341'] },
  crypto_hooks:      { name: 'Crypto Monitor', description: 'Hook Cipher, MessageDigest, SecretKeySpec, IvParameterSpec, Mac', mastg: ['MASTG-TEST-0212','MASTG-TEST-0221'] },
  network_hooks:     { name: 'Network Interceptor', description: 'Log all OkHttp3/HttpURLConnection requests + auth headers', mastg: [] },
  storage_hooks:     { name: 'Storage Monitor', description: 'Hook SharedPrefs, SQLite, KeyStore reads/writes', mastg: ['MASTG-TEST-0001'] },
  dexguard_bypass:   { name: 'DexGuard Bypass', description: 'Universal bypass for DexGuard root/debug/env checks', mastg: ['MASTG-TEST-0045'] },
  appsealing_bypass: { name: 'AppSealing Bypass', description: 'Universal bypass for AppSealing integrity checks', mastg: ['MASTG-TEST-0045'] },
  arxan_bypass:      { name: 'Arxan Bypass', description: 'Universal bypass for Arxan anti-tamper', mastg: ['MASTG-TEST-0045'] },
  ui_hooks:          { name: 'UI Interaction Hook', description: 'Correlate clicks with traffic (Semantic Correlation)', mastg: [] },
  custom:            { name: 'Custom Script', description: 'Write your own Frida JavaScript', mastg: [] },
};

export default function FridaScriptEditor({ appId, packageName, deviceId }) {
  // Mode: 'companion' (live device via WebSocket) | 'apk' (static APK pipeline)
  const [mode, setMode] = useState(deviceId ? 'companion' : 'apk');

  // Script state
  const [selectedTemplate, setSelectedTemplate] = useState('ssl_bypass');
  const [scriptCode, setScriptCode] = useState('');
  const [scriptName, setScriptName] = useState('ssl_bypass');
  const [executing, setExecuting] = useState(false);
  const [savedScripts, setSavedScripts] = useState([]);

  // Session state (companion mode)
  const [sessionId, setSessionId] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const [liveOutput, setLiveOutput] = useState([]);
  const [findings, setFindings] = useState([]);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [capturedTokens, setCapturedTokens] = useState([]);

  // frida-server
  const [serverStatus, setServerStatus] = useState({ running: false, checked: false });

  // Script library (from backend)
  const [library, setLibrary] = useState([]);
  const [libraryLoaded, setLibraryLoaded] = useState(false);

  // MASTG coverage report
  const [mastgReport, setMastgReport] = useState(null);

  // AI hooks
  const [aiPackageName, setAiPackageName] = useState(packageName || '');
  const [aiAuthClasses, setAiAuthClasses] = useState('');
  const [aiGenerating, setAiGenerating] = useState(false);

  // Tab
  const [tab, setTab] = useState('editor');
  const outputRef = useRef(null);
  const pollRef = useRef(null);

  // ── Load script library ──────────────────────────────────────────────────

  useEffect(() => {
    if (libraryLoaded) return;
    const params = packageName ? `?package_name=${encodeURIComponent(packageName)}` : '';
    api.get(`/mobile/frida/library${params}`)
      .then(r => { setLibrary(safeArray(r.data)); setLibraryLoaded(true); })
      .catch(() => setLibraryLoaded(true));
  }, []);

  // ── Load saved scripts from localStorage ────────────────────────────────

  useEffect(() => {
    const saved = localStorage.getItem('frida_saved_scripts');
    if (saved) {
      try { setSavedScripts(JSON.parse(saved)); } catch(e) {}
    }
    setScriptCode(buildPlaceholder(selectedTemplate));
  }, []);

  // ── frida-server status check (companion mode) ───────────────────────────

  useEffect(() => {
    if (!deviceId || mode !== 'companion') return;
    checkServerStatus();
  }, [deviceId, mode]);

  const checkServerStatus = async () => {
    if (!deviceId) return;
    try {
      const r = await api.get(`/mobile/frida/server/status/${deviceId}`);
      setServerStatus({ ...(r.data || {}), checked: true });
    } catch { setServerStatus({ running: false, checked: true }); }
  };

  // ── Session polling (companion mode) ─────────────────────────────────────

  useEffect(() => {
    if (!sessionId) return;
    pollRef.current = setInterval(() => fetchSessionStatus(sessionId), 1500);
    return () => clearInterval(pollRef.current);
  }, [sessionId]);

  const fetchSessionStatus = async (sid) => {
    try {
      const r = await api.get(`/mobile/frida/session/${sid}`);
      const d = r.data || {};
      setSessionStatus(d);
      setFindings(safeArray(d.findings));
      setLiveOutput(safeArray(d.output_log));
      setCapturedTokens(safeArray(d.captured_tokens));
      if (d.status === 'completed' || d.status === 'stopped') {
        clearInterval(pollRef.current);
        setExecuting(false);
      }
    } catch {}
  };

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [liveOutput]);

  // ── Script resolution ─────────────────────────────────────────────────────

  const resolveScriptContent = () => {
    // Try library first
    const libScript = library.find(s => s.name === selectedTemplate);
    if (libScript) return libScript.script_content;
    // Fall back to inline code
    return scriptCode;
  };

  const buildPlaceholder = (template) => {
    if (template === 'custom') {
      return `// Custom Frida Script\nJava.perform(function() {\n    console.log("[*] Script started");\n    // Your code here\n});`;
    }
    return `// ${TEMPLATE_SCRIPTS[template]?.name || template}\n// Click "Execute" to inject the full generated script via the library.`;
  };

  const handleTemplateChange = (key) => {
    setSelectedTemplate(key);
    setScriptName(key);
    setScriptCode(buildPlaceholder(key));
    setFindings([]);
    setLiveOutput([]);
  };

  // ── Execute ───────────────────────────────────────────────────────────────

  const handleExecute = async () => {
    if (!scriptName) return;
    setExecuting(true);
    setFindings([]);
    setLiveOutput([]);
    setMastgReport(null);

    try {
      if (mode === 'companion') {
        await executeCompanion();
      } else {
        await executeApkPipeline();
      }
    } catch (e) {
      setLiveOutput([`[error] ${e.message}`]);
      setExecuting(false);
    }
  };

  const executeCompanion = async () => {
    if (!deviceId || !aiPackageName) {
      setLiveOutput(['[error] Device ID and package name required for companion mode']);
      setExecuting(false);
      return;
    }

    if (selectedTemplate === 'custom' && scriptCode.trim()) {
      const r = await api.post('/mobile/frida/inject', {
        device_id: deviceId,
        package_name: aiPackageName,
        script_name: 'custom',
        script_content: scriptCode,
      });
      setSessionId((r.data || {}).session_id);
      return;
    }

    const r = await api.post('/mobile/frida/session/start', {
      device_id: deviceId,
      package_name: aiPackageName,
      scripts: selectedTemplate !== 'custom' ? [selectedTemplate] : [],
    });
    const d = r.data || {};
    setSessionId(d.session_id);
    setLiveOutput([`[session] ${d.session_id} started — ${d.scripts_queued} script(s) injected`]);
  };

  const executeApkPipeline = async () => {
    if (!appId) {
      setLiveOutput(['[error] appId required for APK pipeline mode']);
      setExecuting(false);
      return;
    }
    const r = await api.post(`/mobile/apps/${appId}/frida`, {
      script_content: resolveScriptContent(),
      script_name: scriptName,
      timeout: 60,
      device_id: deviceId || '',
    });
    const d = r.data || {};
    setFindings(safeArray(d.findings).map(f => ({
      vulnerability: f.vulnerability,
      attack_type: f.attack_type,
      severity: f.severity,
      evidence: f.evidence,
      confidence: f.confidence || 0.8,
      mastg_ids: TEMPLATE_SCRIPTS[selectedTemplate]?.mastg || [],
    })));
    setLiveOutput(safeArray(d.output));
    setExecuting(false);
  };

  // ── AI Hook generation ────────────────────────────────────────────────────

  const handleAiGenerate = async () => {
    if (!aiPackageName) return;
    setAiGenerating(true);
    try {
      const r = await api.post('/mobile/frida/hook/ai-generate', {
        package_name: aiPackageName,
        auth_classes: aiAuthClasses.split('\n').map(s => s.trim()).filter(Boolean),
        crypto_classes: [],
        network_classes: [],
      });
      const d = r.data || {};
      const scripts = safeArray(d.scripts);
      if (scripts.length > 0) {
        setScriptCode(scripts[0].script_content);
        setScriptName(scripts[0].name);
        setSelectedTemplate('custom');
        setLiveOutput([`[ai] Generated ${d.scripts_generated} targeted hook(s) for ${aiPackageName}`]);
      }
    } catch (e) {
      setLiveOutput([`[ai] Generation failed: ${e.response?.data?.detail || e.message}`]);
    }
    setAiGenerating(false);
  };

  // ── MASTG Report ──────────────────────────────────────────────────────────

  const fetchMastgReport = async () => {
    if (!sessionId) return;
    try {
      const r = await api.get(`/mobile/frida/mastg/report/${sessionId}`);
      setMastgReport(r.data || null);
      setTab('mastg');
    } catch {}
  };

  // ── Save ──────────────────────────────────────────────────────────────────

  const handleSave = () => {
    const entry = { id: Date.now().toString(), name: scriptName, code: scriptCode, created_at: new Date().toISOString() };
    const updated = [...savedScripts, entry];
    setSavedScripts(updated);
    localStorage.setItem('frida_saved_scripts', JSON.stringify(updated));
  };

  const handleDeleteSaved = (id) => {
    const updated = savedScripts.filter(s => s.id !== id);
    setSavedScripts(updated);
    localStorage.setItem('frida_saved_scripts', JSON.stringify(updated));
  };

  // ── Render ────────────────────────────────────────────────────────────────

  const s = styles;

  return (
    <div style={s.container}>
      {/* Header */}
      <div style={s.header}>
        <div style={s.headerLeft}>
          <Terminal size={20} style={{ color: '#a855f7' }} />
          <div>
            <div style={s.title}>Frida Script Lab</div>
            <div style={s.subtitle}>Dynamic instrumentation · MASTG-guided · Attack bridge</div>
          </div>
        </div>
        <div style={s.headerRight}>
          {/* Mode toggle */}
          <div style={s.modeToggle}>
            {['companion', 'apk'].map(m => (
              <button key={m} onClick={() => setMode(m)}
                style={{ ...s.modeBtn, ...(mode === m ? s.modeBtnActive : {}) }}>
                {m === 'companion' ? '📱 Companion' : '📦 APK Pipeline'}
              </button>
            ))}
          </div>
          {/* frida-server status (companion mode) */}
          {mode === 'companion' && deviceId && (
            <div style={s.serverStatus}>
              <div style={{ width: 8, height: 8, borderRadius: 4,
                            background: serverStatus.running ? '#00ff88' : '#ff4444' }} />
              <span style={{ fontSize: 11, color: serverStatus.running ? '#00ff88' : '#888' }}>
                {serverStatus.running ? 'frida-server' : 'server offline'}
              </span>
              <button onClick={checkServerStatus} style={s.refreshBtn}><RefreshCw size={10} /></button>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={s.tabs}>
        {[
          { id: 'editor', label: '✏️ Script Editor' },
          { id: 'output', label: `📋 Output${liveOutput.length ? ` (${liveOutput.length})` : ''}` },
          { id: 'findings', label: `🎯 Findings${findings.length ? ` (${findings.length})` : ''}` },
          { id: 'ai', label: '🤖 AI Hooks' },
          { id: 'mastg', label: `📊 MASTG${mastgReport ? ` (${mastgReport.summary?.coverage_pct}%)` : ''}` },
        ].map(({ id, label }) => (
          <button key={id} onClick={() => setTab(id)}
            style={{ ...s.tab, ...(tab === id ? s.tabActive : {}) }}>
            {label}
          </button>
        ))}
      </div>

      {/* ── EDITOR TAB ── */}
      {tab === 'editor' && (
        <div style={s.editorLayout}>
          {/* Sidebar */}
          <div style={s.sidebar}>
            <div style={s.sideLabel}>SCRIPT LIBRARY</div>
            {Object.entries(TEMPLATE_SCRIPTS).map(([key, tpl]) => {
              const libEntry = library.find(s => s.name === key);
              return (
                <button key={key} onClick={() => handleTemplateChange(key)}
                  style={{ ...s.tplBtn, ...(selectedTemplate === key ? s.tplBtnActive : {}) }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                    {CAT_ICON[key.split('_')[0]] || <Code size={11} />}
                    <span style={{ fontSize: 11, fontWeight: 700 }}>{tpl.name}</span>
                    {libEntry && <span style={s.libBadge}>LIB</span>}
                  </div>
                  <div style={{ fontSize: 10, color: '#555', lineHeight: 1.4 }}>{tpl.description}</div>
                  {tpl.mastg.length > 0 && (
                    <div style={{ marginTop: 4, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                      {tpl.mastg.map(m => <span key={m} style={s.mastgChip}>{m.replace('MASTG-TEST-','')}</span>)}
                    </div>
                  )}
                </button>
              );
            })}

            {savedScripts.length > 0 && (
              <>
                <div style={{ ...s.sideLabel, marginTop: 12 }}>SAVED SCRIPTS</div>
                {savedScripts.map(sc => (
                  <div key={sc.id} style={s.savedEntry}>
                    <button onClick={() => { setScriptCode(sc.code); setScriptName(sc.name); setSelectedTemplate('custom'); }}
                      style={{ fontSize: 11, color: '#ccc', fontWeight: 700, background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}>
                      {sc.name}
                    </button>
                    <button onClick={() => handleDeleteSaved(sc.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ff4444', marginLeft: 4 }}>
                      <XCircle size={11} />
                    </button>
                  </div>
                ))}
              </>
            )}
          </div>

          {/* Editor area */}
          <div style={s.editorArea}>
            {mode === 'companion' && (
              <div style={s.pkgRow}>
                <input value={aiPackageName} onChange={e => setAiPackageName(e.target.value)}
                  placeholder="Package name (e.g. com.target.app)"
                  style={{ ...s.input, flex: 1 }} />
              </div>
            )}

            <div style={s.scriptNameRow}>
              <input value={scriptName} onChange={e => setScriptName(e.target.value)}
                placeholder="script_name" style={{ ...s.input, flex: 1 }} />
              <button onClick={handleSave} style={{ ...s.btn, background: '#0a2030', borderColor: '#0055aa' }}>
                <Save size={12} /> Save
              </button>
              <button onClick={handleExecute} disabled={executing}
                style={{ ...s.btn, background: '#330022', borderColor: '#880044',
                         opacity: executing ? 0.5 : 1, cursor: executing ? 'not-allowed' : 'pointer' }}>
                {executing ? <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={12} />}
                {executing ? 'Running…' : 'Execute'}
              </button>
            </div>

            <textarea value={scriptCode} onChange={e => setScriptCode(e.target.value)}
              style={s.codeArea}
              placeholder="Java.perform(function() { ... });"
              spellCheck={false} />

            <div style={s.codeFooter}>
              <span>{scriptCode.split('\n').length} lines · {scriptCode.length} chars</span>
              {selectedTemplate !== 'custom' && library.find(l => l.name === selectedTemplate) && (
                <span style={{ color: '#00ff88' }}>✓ Full script loaded from library</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── OUTPUT TAB ── */}
      {tab === 'output' && (
        <div style={s.outputPanel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: '#666' }}>{liveOutput.length} lines</span>
            {sessionId && (
              <button onClick={fetchMastgReport} style={{ ...s.btn, fontSize: 10 }}>
                📊 Generate MASTG Report
              </button>
            )}
          </div>
          <pre ref={outputRef} style={s.outputPre}>
            {liveOutput.join('\n') || 'No output yet. Execute a script first.'}
          </pre>
          {capturedTokens.length > 0 && (
            <div style={s.tokenAlert}>
              ⚡ {capturedTokens.length} auth token(s) captured → Attack campaign launched
            </div>
          )}
        </div>
      )}

      {/* ── FINDINGS TAB ── */}
      {tab === 'findings' && (
        <div>
          {findings.length === 0 ? (
            <div style={s.empty}>No findings yet. Execute a script to start instrumentation.</div>
          ) : (
            findings.map((f, i) => (
              <div key={i} onClick={() => setExpandedFinding(expandedFinding === i ? null : i)}
                style={{ ...s.findingCard, borderLeft: `3px solid ${SEV_COLOR[f.severity] || '#888'}`,
                         background: SEV_BG[f.severity] || '#111' }}>
                <div style={s.findingHeader}>
                  <span style={{ color: SEV_COLOR[f.severity], fontSize: 10, fontWeight: 700 }}>
                    [{(f.severity || 'info').toUpperCase()}]
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 700, marginLeft: 8 }}>{f.vulnerability}</span>
                  {(f.mastg_ids || []).map(m => <span key={m} style={s.mastgBadge}>{m}</span>)}
                  {(f.masvs_ids || []).map(m => <span key={m} style={s.mavsBadge}>{m}</span>)}
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#555' }}>
                    {((f.confidence || 0) * 100).toFixed(0)}% confidence
                  </span>
                </div>
                {expandedFinding === i && (
                  <div style={s.findingDetail}>
                    <div><span style={s.detailKey}>Evidence: </span><span style={{ color: '#ff8800' }}>{f.evidence}</span></div>
                    <div><span style={s.detailKey}>Attack type: </span><code style={s.code}>{f.attack_type}</code></div>
                    {f.remediation && <div><span style={s.detailKey}>Remediation: </span><span style={{ color: '#88ff88', fontSize: 11 }}>{f.remediation}</span></div>}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* ── AI HOOKS TAB ── */}
      {tab === 'ai' && (
        <div style={s.aiPanel}>
          <div style={s.aiDesc}>
            AI Hook Generation uses the existing FridaScriptGenerator to produce targeted instrumentation
            hooks for specific auth/crypto/network classes discovered during reverse engineering.
          </div>
          <div style={s.field}>
            <label style={s.fieldLabel}>Package Name</label>
            <input value={aiPackageName} onChange={e => setAiPackageName(e.target.value)}
              placeholder="com.target.app" style={s.input} />
          </div>
          <div style={s.field}>
            <label style={s.fieldLabel}>Auth Classes (one per line)</label>
            <textarea value={aiAuthClasses} onChange={e => setAiAuthClasses(e.target.value)}
              placeholder="com.target.auth.LoginManager&#10;com.target.auth.TokenValidator"
              rows={4} style={{ ...s.input, resize: 'vertical', fontFamily: 'monospace', fontSize: 11 }} />
          </div>
          <button onClick={handleAiGenerate} disabled={aiGenerating || !aiPackageName}
            style={{ ...s.btn, background: '#2a0044', borderColor: '#8800cc', marginTop: 8 }}>
            {aiGenerating ? <Loader size={12} /> : <Zap size={12} />}
            {aiGenerating ? 'Generating…' : 'Generate Targeted Hooks'}
          </button>
          {liveOutput.filter(l => l.includes('[ai]')).map((l, i) => (
            <div key={i} style={{ fontSize: 11, color: '#a855f7', marginTop: 8 }}>{l}</div>
          ))}
        </div>
      )}

      {/* ── MASTG TAB ── */}
      {tab === 'mastg' && (
        <div>
          {!mastgReport ? (
            <div style={s.empty}>
              Run scripts first, then click "Generate MASTG Report" in the Output tab.
            </div>
          ) : (
            <>
              <div style={s.mastgSummary}>
                <div style={s.mastgStatCard}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: '#ff4444' }}>{mastgReport.summary.failed}</div>
                  <div style={s.mastgStatLabel}>Failed</div>
                </div>
                <div style={s.mastgStatCard}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: '#00ff88' }}>{mastgReport.summary.passed}</div>
                  <div style={s.mastgStatLabel}>Passed</div>
                </div>
                <div style={s.mastgStatCard}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: '#888' }}>{mastgReport.summary.not_tested}</div>
                  <div style={s.mastgStatLabel}>Not Tested</div>
                </div>
                <div style={s.mastgStatCard}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: '#00aaff' }}>{mastgReport.summary.coverage_pct}%</div>
                  <div style={s.mastgStatLabel}>Coverage</div>
                </div>
                {mastgReport.phase2_chains_triggered > 0 && (
                  <div style={{ ...s.mastgStatCard, borderColor: '#ff4400' }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: '#ff6600' }}>{mastgReport.phase2_chains_triggered}</div>
                    <div style={s.mastgStatLabel}>Attack Chains</div>
                  </div>
                )}
              </div>
              <div style={{ marginTop: 12 }}>
                {(mastgReport.coverage || []).map(c => (
                  <div key={c.mastg_id} style={{ ...s.mastgRow, borderLeft: `3px solid ${c.status === 'FAIL' ? '#ff2244' : c.status === 'PASS' ? '#00ff88' : '#333'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ ...s.mastgStatus, color: c.status === 'FAIL' ? '#ff2244' : c.status === 'PASS' ? '#00ff88' : '#555' }}>
                        {c.status}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 700 }}>{c.mastg_id}</span>
                      <span style={{ fontSize: 11, color: '#aaa' }}>{c.title}</span>
                      <span style={{ marginLeft: 'auto', fontSize: 10, color: '#555' }}>[{c.category}]</span>
                    </div>
                    {c.masvs.length > 0 && (
                      <div style={{ marginTop: 3 }}>
                        {c.masvs.map(m => <span key={m} style={s.mavsBadge}>{m}</span>)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = {
  container:    { background: 'transparent', color: '#ddd', fontFamily: 'monospace', padding: 0, borderRadius: 0 },
  header:       { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: '#0d0d0d', borderBottom: '1px solid #1a1a1a', flexWrap: 'wrap', gap: 8 },
  headerLeft:   { display: 'flex', alignItems: 'center', gap: 10 },
  headerRight:  { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' },
  title:        { fontSize: 13, fontWeight: 900, color: '#a855f7', textTransform: 'uppercase', letterSpacing: 1 },
  subtitle:     { fontSize: 9, color: '#444', marginTop: 2 },
  modeToggle:   { display: 'flex', gap: 2, background: '#000', padding: 2, borderRadius: 6, border: '1px solid #222' },
  modeBtn:      { padding: '3px 8px', background: 'transparent', border: 'none', color: '#444', borderRadius: 4, cursor: 'pointer', fontSize: 9, fontWeight: 'bold', textTransform: 'uppercase' },
  modeBtnActive:{ background: '#a855f7', color: '#000' },
  serverStatus: { display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', background: '#000', borderRadius: 6, border: '1px solid #1a1a1a' },
  refreshBtn:   { background: 'none', border: 'none', cursor: 'pointer', color: '#444', padding: 0 },
  tabs:         { display: 'flex', gap: 1, padding: '8px 16px', background: '#080808', borderBottom: '1px solid #1a1a1a' },
  tab:          { padding: '6px 12px', background: 'transparent', border: 'none', color: '#555', cursor: 'pointer', fontSize: 10, fontWeight: 700, textTransform: 'uppercase' },
  tabActive:    { color: '#a855f7', boxShadow: 'inset 0 -2px 0 #a855f7' },
  editorLayout: { display: 'grid', gridTemplateColumns: '240px 1fr', height: '600px' },
  sidebar:      { display: 'flex', flexDirection: 'column', gap: 1, padding: 8, background: '#0d0d0d', borderRight: '1px solid #1a1a1a', overflowY: 'auto' },
  sideLabel:    { fontSize: 9, color: '#333', fontWeight: 900, letterSpacing: 2, padding: '8px 4px', textTransform: 'uppercase' },
  tplBtn:       { padding: '10px 12px', background: 'transparent', border: '1px solid transparent', borderRadius: 8, cursor: 'pointer', textAlign: 'left', transition: 'all 0.2s' },
  tplBtnActive: { background: '#1a1a1a', borderColor: '#333', boxShadow: '0 4px 12px rgba(0,0,0,0.5)' },
  libBadge:     { fontSize: 7, background: '#002200', color: '#00ff88', padding: '1px 4px', borderRadius: 4, fontWeight: 'black' },
  mastgChip:    { fontSize: 7, background: '#001133', color: '#4488ff', padding: '1px 4px', borderRadius: 4, fontWeight: 'bold' },
  savedEntry:   { display: 'flex', alignItems: 'center', padding: '4px 8px', background: '#000', borderRadius: 6, border: '1px solid #111' },
  editorArea:   { display: 'flex', flexDirection: 'column', background: '#050505' },
  pkgRow:       { padding: '12px 16px', background: '#0d0d0d', borderBottom: '1px solid #111' },
  scriptNameRow:{ display: 'flex', gap: 8, padding: '12px 16px', background: '#0d0d0d', borderBottom: '1px solid #111' },
  input:        { background: '#000', border: '1px solid #222', color: '#eee', padding: '8px 12px', borderRadius: 6, fontSize: 11, outline: 'none', flex: 1, fontFamily: 'monospace' },
  btn:          { display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', border: '1px solid #333', borderRadius: 6, cursor: 'pointer', fontSize: 10, fontWeight: 900, color: '#bbb', textTransform: 'uppercase', transition: 'all 0.2s' },
  codeArea:     { flex: 1, background: 'transparent', border: 'none', color: '#00ff88', padding: 20, fontSize: 12, resize: 'none', fontFamily: '"Fira Code", monospace', outline: 'none', lineHeight: 1.6 },
  codeFooter:   { display: 'flex', justifyContent: 'space-between', padding: '8px 16px', fontSize: 9, color: '#333', background: '#0d0d0d', borderTop: '1px solid #111' },
  outputPanel:  { display: 'flex', flexDirection: 'column', height: '600px', background: '#050505' },
  outputPre:    { flex: 1, background: 'transparent', color: '#00ff88', padding: 20, fontSize: 11, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: '"Fira Code", monospace' },
  tokenAlert:   { background: '#1a0800', borderTop: '1px solid #ff4400', padding: '12px 16px', fontSize: 10, color: '#ff6600', fontWeight: 'bold' },
  findingCard:  { padding: '12px 16px', borderBottom: '1px solid #111', cursor: 'pointer', transition: 'all 0.2s' },
  findingHeader:{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 },
  mastgBadge:   { fontSize: 8, background: '#001133', color: '#4488ff', padding: '2px 6px', borderRadius: 4, border: '1px solid #003366', fontWeight: 'bold' },
  mavsBadge:    { fontSize: 8, background: '#002200', color: '#00ff88', padding: '2px 6px', borderRadius: 4, border: '1px solid #004400', fontWeight: 'bold' },
  findingDetail:{ marginTop: 12, padding: 12, background: '#000', borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11, border: '1px solid #1a1a1a' },
  detailKey:    { color: '#444', marginRight: 4, textTransform: 'uppercase', fontSize: 9, fontWeight: 'bold' },
  code:         { background: '#1a1a00', color: '#ffff00', padding: '2px 6px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace' },
  aiPanel:      { padding: 20, display: 'flex', flexDirection: 'column', gap: 16, background: '#050505', height: '600px' },
  aiDesc:       { fontSize: 11, color: '#666', background: '#0d0d0d', padding: 16, borderRadius: 8, lineHeight: 1.6, border: '1px solid #111' },
  field:        { display: 'flex', flexDirection: 'column', gap: 6 },
  fieldLabel:   { fontSize: 9, color: '#444', fontWeight: 900, textTransform: 'uppercase', letterSpacing: 1 },
  mastgSummary: { display: 'flex', gap: 10, padding: 16, background: '#0d0d0d', borderBottom: '1px solid #111' },
  mastgStatCard:{ flex: 1, background: '#000', border: '1px solid #1a1a1a', borderRadius: 8, padding: '12px', textAlign: 'center' },
  mastgStatLabel:{ fontSize: 8, color: '#444', marginTop: 4, textTransform: 'uppercase', fontWeight: 'bold' },
  mastgRow:     { background: '#0d0d0d', padding: '12px 16px', borderBottom: '1px solid #111' },
  mastgStatus:  { fontSize: 9, fontWeight: 900, minWidth: 60, textTransform: 'uppercase' },
  empty:        { color: '#333', fontSize: 12, padding: '60px 0', textAlign: 'center', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: 2 },
};
