import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../utils/api';

const safeArray = (v) => (Array.isArray(v) ? v : []);

const SEVERITY_COLORS = {
  critical: '#ff2244',
  high: '#ff6600',
  medium: '#ffaa00',
  low: '#44aaff',
  info: '#888',
};

const STATUS_COLORS = {
  running: '#00ff88',
  completed: '#44aaff',
  stopped: '#888',
  error: '#ff2244',
  pending: '#ffaa00',
};

export default function AttackLauncher({ deviceId, capturedTraffic = [] }) {
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState('full_owasp_mobile');
  const [sessions, setSessions] = useState([]);
  const [activeSession, setActiveSession] = useState(null);
  const [sessionDetails, setSessionDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [customEndpoints, setCustomEndpoints] = useState('');
  const [injectForm, setInjectForm] = useState({
    url_pattern: '', param: '', payload: '', vuln_type: 'sqli', position: 'body'
  });
  const [injectStatus, setInjectStatus] = useState('');
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [tab, setTab] = useState('launch');
  const pollRef = useRef(null);

  // Load templates on mount
  useEffect(() => {
    api.get('/mobile/attack/templates')
      .then(r => setTemplates(safeArray(r.data)))
      .catch(() => {});
    fetchSessions();
  }, []);

  // Poll active session
  useEffect(() => {
    if (!activeSession) {
      clearInterval(pollRef.current);
      return;
    }
    pollRef.current = setInterval(() => {
      fetchSessionDetails(activeSession);
    }, 1500);
    return () => clearInterval(pollRef.current);
  }, [activeSession]);

  const fetchSessions = async () => {
    try {
      const r = await api.get('/mobile/attack/sessions');
      setSessions(safeArray(r.data));
    } catch {}
  };

  const fetchSessionDetails = useCallback(async (sessionId) => {
    try {
      const r = await api.get(`/mobile/attack/session/${sessionId}/status`);
      const data = r.data || {};
      setSessionDetails(data);
      if (data.status === 'completed' || data.status === 'stopped' || data.status === 'error') {
        clearInterval(pollRef.current);
      }
    } catch {}
  }, []);

  // Collect endpoints from captured traffic + custom input
  const collectEndpoints = () => {
    const fromTraffic = capturedTraffic
      .map(e => e.request?.url)
      .filter(u => u && u.startsWith('http'));
    const fromInput = customEndpoints
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.startsWith('http'));
    return [...new Set([...fromTraffic, ...fromInput])];
  };

  const startAttack = async () => {
    const endpoints = collectEndpoints();
    if (!endpoints.length) {
      setError('No endpoints found. Capture some traffic first or enter endpoints manually.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const r = await api.post('/mobile/attack/session/start', {
        device_id: deviceId || '',
        endpoints,
        template_id: selectedTemplate,
        options: { timeout: 10 },
      });
      const data = r.data || {};
      if (data.session_id) {
        setActiveSession(data.session_id);
        setTab('session');
        fetchSessions();
      }
    } catch (e) {
      setError(`Failed to start attack: ${e.response?.data?.detail || e.message}`);
    }
    setLoading(false);
  };

  const stopSession = async (sessionId) => {
    try { await api.delete(`/mobile/attack/session/${sessionId}`); } catch {}
    clearInterval(pollRef.current);
    setActiveSession(null);
    fetchSessions();
    fetchSessionDetails(sessionId);
  };

  const injectPayload = async () => {
    if (!deviceId) { setInjectStatus('No device selected'); return; }
    if (!injectForm.payload) { setInjectStatus('Payload is required'); return; }
    setInjectStatus('Sending...');
    try {
      const r = await api.post('/mobile/attack/inject', { device_id: deviceId, ...injectForm });
      const data = r.data || {};
      setInjectStatus(data.status === 'injected'
        ? `✓ Injected [${data.injection_id}] — waiting for matching request`
        : `Error: ${JSON.stringify(data)}`);
    } catch (e) {
      setInjectStatus(`Failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  const selectedTpl = templates.find(t => t.id === selectedTemplate);
  const findings = sessionDetails?.findings || [];
  const chainLog = sessionDetails?.chain_log || [];
  const stats = sessionDetails?.stats || {};
  const wafProfile = sessionDetails?.waf_profile || {};

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <span style={styles.title}>⚡ Attack Launcher</span>
        <span style={styles.subtitle}>OWASP Mobile Top 10 · WAF-Adaptive · Chain Sequencer</span>
        {deviceId && <span style={styles.deviceBadge}>🔗 {deviceId.substring(0, 8)}…</span>}
      </div>

      {/* Tabs */}
      <div style={styles.tabs}>
        {['launch', 'inject', 'session', 'sessions'].map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{ ...styles.tab, ...(tab === t ? styles.tabActive : {}) }}
          >
            {{ launch: '🚀 Launch', inject: '💉 Inject', session: '📊 Session', sessions: '📋 All Sessions' }[t]}
          </button>
        ))}
      </div>

      {/* ── LAUNCH TAB ── */}
      {tab === 'launch' && (
        <div style={styles.panel}>
          <div style={styles.section}>
            <label style={styles.label}>Attack Template</label>
            <select
              value={selectedTemplate}
              onChange={e => setSelectedTemplate(e.target.value)}
              style={styles.select}
            >
              {templates.map(t => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            {selectedTpl && (
              <div style={styles.tplInfo}>
                <span style={{ color: SEVERITY_COLORS[selectedTpl.severity] }}>
                  [{selectedTpl.severity.toUpperCase()}]
                </span>{' '}
                {selectedTpl.description}
                <br />
                <span style={styles.mono}>{selectedTpl.owasp_ref}</span>
                {selectedTpl.chain_on_success?.length > 0 && (
                  <span style={styles.chainHint}>
                    → chains to: {selectedTpl.chain_on_success.join(', ')}
                  </span>
                )}
              </div>
            )}
          </div>

          <div style={styles.section}>
            <label style={styles.label}>
              Target Endpoints
              {capturedTraffic.length > 0 && (
                <span style={styles.badge}>{capturedTraffic.length} from traffic</span>
              )}
            </label>
            <textarea
              value={customEndpoints}
              onChange={e => setCustomEndpoints(e.target.value)}
              placeholder={'https://api.example.com/users/1\nhttps://api.example.com/login\n(one URL per line — auto-populated from captured traffic)'}
              style={styles.textarea}
              rows={5}
            />
            <div style={styles.endpointCount}>
              {collectEndpoints().length} endpoint(s) queued
            </div>
          </div>

          {error && <div style={styles.error}>{error}</div>}

          <button
            onClick={startAttack}
            disabled={loading}
            style={{ ...styles.btn, ...styles.btnRed, ...(loading ? styles.btnDisabled : {}) }}
          >
            {loading ? '⏳ Starting…' : '⚡ Launch Attack Campaign'}
          </button>
        </div>
      )}

      {/* ── INJECT TAB ── */}
      {tab === 'inject' && (
        <div style={styles.panel}>
          <div style={styles.infoBox}>
            Mid-flight injection sends a command to the Android companion. The next HTTP request
            matching the URL pattern will have the payload inserted into it <em>inside</em> the
            device VPN tunnel — no external proxy needed.
          </div>

          <div style={styles.grid2}>
            <div style={styles.field}>
              <label style={styles.label}>URL Pattern (partial match)</label>
              <input
                value={injectForm.url_pattern}
                onChange={e => setInjectForm(f => ({ ...f, url_pattern: e.target.value }))}
                placeholder="api/login"
                style={styles.input}
              />
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Parameter Name</label>
              <input
                value={injectForm.param}
                onChange={e => setInjectForm(f => ({ ...f, param: e.target.value }))}
                placeholder="username"
                style={styles.input}
              />
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Payload</label>
              <input
                value={injectForm.payload}
                onChange={e => setInjectForm(f => ({ ...f, payload: e.target.value }))}
                placeholder="' OR '1'='1"
                style={styles.input}
              />
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Vulnerability Type</label>
              <select
                value={injectForm.vuln_type}
                onChange={e => setInjectForm(f => ({ ...f, vuln_type: e.target.value }))}
                style={styles.select}
              >
                {['sqli', 'xss', 'ssrf', 'ssti', 'cmdi', 'idor', 'auth_bypass', 'mass_assignment'].map(v => (
                  <option key={v} value={v}>{v.toUpperCase()}</option>
                ))}
              </select>
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Injection Position</label>
              <select
                value={injectForm.position}
                onChange={e => setInjectForm(f => ({ ...f, position: e.target.value }))}
                style={styles.select}
              >
                {['body', 'query', 'header'].map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
          </div>

          <button onClick={injectPayload} style={{ ...styles.btn, ...styles.btnOrange }}>
            💉 Inject Payload
          </button>
          {injectStatus && (
            <div style={{ ...styles.infoBox, marginTop: 8, color: injectStatus.startsWith('✓') ? '#00ff88' : '#ff8800' }}>
              {injectStatus}
            </div>
          )}
        </div>
      )}

      {/* ── SESSION TAB ── */}
      {tab === 'session' && (
        <div style={styles.panel}>
          {!sessionDetails && !activeSession && (
            <div style={styles.empty}>No active session. Launch an attack first.</div>
          )}

          {sessionDetails && (
            <>
              {/* Session header */}
              <div style={styles.sessionHeader}>
                <div>
                  <span style={styles.sessionId}>{sessionDetails.session_id}</span>
                  <span style={{
                    ...styles.statusBadge,
                    backgroundColor: STATUS_COLORS[sessionDetails.status] || '#888',
                  }}>
                    {sessionDetails.status}
                  </span>
                  {wafProfile.detected && (
                    <span style={styles.wafBadge}>🛡 {wafProfile.waf_name} — bypass active</span>
                  )}
                </div>
                {sessionDetails.status === 'running' && (
                  <button
                    onClick={() => stopSession(sessionDetails.session_id)}
                    style={{ ...styles.btn, ...styles.btnSmall, background: '#333' }}
                  >
                    ■ Stop
                  </button>
                )}
              </div>

              {/* Stats row */}
              <div style={styles.statsRow}>
                {[
                  ['Endpoints Tested', stats.endpoints_tested || 0],
                  ['Attacks Run', stats.attacks_run || 0],
                  ['Findings', stats.findings_count || 0, '#ff6600'],
                  ['Chains Triggered', stats.chains_triggered || 0, '#00aaff'],
                  ['Duration', `${sessionDetails.duration_s || 0}s`],
                ].map(([label, val, color]) => (
                  <div key={label} style={styles.statCard}>
                    <div style={{ ...styles.statVal, color: color || '#fff' }}>{val}</div>
                    <div style={styles.statLabel}>{label}</div>
                  </div>
                ))}
              </div>

              {/* Chain log */}
              {chainLog.length > 0 && (
                <div style={styles.chainBox}>
                  <div style={styles.sectionTitle}>⛓ Attack Chain Log</div>
                  {chainLog.map((entry, i) => (
                    <div key={i} style={styles.chainEntry}>{entry}</div>
                  ))}
                </div>
              )}

              {/* Findings */}
              <div style={styles.sectionTitle}>
                🎯 Findings ({findings.length})
              </div>
              {findings.length === 0 ? (
                <div style={styles.empty}>
                  {sessionDetails.status === 'running' ? '⏳ Scanning…' : 'No findings'}
                </div>
              ) : (
                <div style={styles.findingsList}>
                  {findings.map((f, i) => (
                    <div
                      key={f.finding_id || i}
                      style={{
                        ...styles.findingCard,
                        borderLeft: `3px solid ${SEVERITY_COLORS[f.severity] || '#888'}`,
                      }}
                      onClick={() => setExpandedFinding(expandedFinding === i ? null : i)}
                    >
                      <div style={styles.findingHeader}>
                        <span style={{ color: SEVERITY_COLORS[f.severity] }}>
                          [{f.severity?.toUpperCase()}]
                        </span>{' '}
                        <span style={styles.findingTitle}>{f.title || f.vuln_type}</span>
                        {f.waf_bypassed && <span style={styles.wafBypassed}>WAF bypassed</span>}
                      </div>
                      <div style={styles.findingUrl}>{f.url}</div>
                      {expandedFinding === i && (
                        <div style={styles.findingDetail}>
                          {f.payload && (
                            <div>
                              <span style={styles.detailLabel}>Payload: </span>
                              <code style={styles.code}>{f.payload}</code>
                            </div>
                          )}
                          {f.evidence && (
                            <div>
                              <span style={styles.detailLabel}>Evidence: </span>
                              <span style={styles.evidence}>{f.evidence}</span>
                            </div>
                          )}
                          {f.remediation && (
                            <div>
                              <span style={styles.detailLabel}>Remediation: </span>
                              <span style={styles.remediation}>{f.remediation}</span>
                            </div>
                          )}
                          <div style={styles.detailMeta}>
                            CVSS: {f.cvss || '?'} · Confidence: {((f.confidence || 0) * 100).toFixed(0)}%
                            {f.timing_baseline_ms && (
                              <> · Timing: {f.timing_attack_ms?.toFixed(0)}ms vs {f.timing_baseline_ms?.toFixed(0)}ms baseline</>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ── ALL SESSIONS TAB ── */}
      {tab === 'sessions' && (
        <div style={styles.panel}>
          <button onClick={fetchSessions} style={{ ...styles.btn, ...styles.btnSmall, marginBottom: 12 }}>
            ↻ Refresh
          </button>
          {sessions.length === 0 ? (
            <div style={styles.empty}>No sessions yet.</div>
          ) : (
            sessions.map(s => (
              <div key={s.session_id} style={styles.sessionRow}
                onClick={() => { setActiveSession(s.session_id); fetchSessionDetails(s.session_id); setTab('session'); }}>
                <div>
                  <span style={styles.sessionId}>{s.session_id}</span>
                  <span style={{ ...styles.statusBadge, backgroundColor: STATUS_COLORS[s.status] || '#888' }}>
                    {s.status}
                  </span>
                </div>
                <div style={styles.sessionMeta}>
                  {s.stats?.findings_count || 0} findings · {s.template_id} · {s.duration_s}s
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = {
  container: { background: '#0d0d0d', color: '#eee', fontFamily: 'monospace', padding: 16, borderRadius: 8, minHeight: 400 },
  header: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, flexWrap: 'wrap' },
  title: { fontSize: 18, fontWeight: 700, color: '#ff4444' },
  subtitle: { fontSize: 11, color: '#666' },
  deviceBadge: { fontSize: 11, color: '#00ff88', background: '#001a0d', padding: '2px 8px', borderRadius: 4 },
  tabs: { display: 'flex', gap: 4, marginBottom: 16 },
  tab: { padding: '6px 14px', background: '#1a1a1a', border: '1px solid #333', borderRadius: 4, color: '#888', cursor: 'pointer', fontSize: 12 },
  tabActive: { background: '#222', borderColor: '#ff4444', color: '#fff' },
  panel: { padding: 0 },
  section: { marginBottom: 16 },
  label: { display: 'block', fontSize: 11, color: '#888', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 },
  select: { width: '100%', background: '#111', border: '1px solid #333', color: '#eee', padding: '8px 12px', borderRadius: 4, fontSize: 13 },
  textarea: { width: '100%', background: '#111', border: '1px solid #333', color: '#eee', padding: '8px 12px', borderRadius: 4, fontSize: 12, resize: 'vertical', boxSizing: 'border-box' },
  input: { width: '100%', background: '#111', border: '1px solid #333', color: '#eee', padding: '8px 12px', borderRadius: 4, fontSize: 13, boxSizing: 'border-box' },
  tplInfo: { marginTop: 8, fontSize: 12, color: '#aaa', lineHeight: 1.6 },
  mono: { color: '#555', fontSize: 11 },
  chainHint: { display: 'block', color: '#00aaff', fontSize: 11, marginTop: 4 },
  badge: { marginLeft: 8, fontSize: 10, background: '#003322', color: '#00ff88', padding: '1px 6px', borderRadius: 10 },
  endpointCount: { marginTop: 4, fontSize: 11, color: '#555' },
  btn: { padding: '10px 20px', borderRadius: 4, border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600, color: '#fff' },
  btnRed: { background: '#cc1133' },
  btnOrange: { background: '#cc5500' },
  btnSmall: { padding: '4px 12px', fontSize: 11, fontWeight: 400 },
  btnDisabled: { opacity: 0.5, cursor: 'not-allowed' },
  error: { color: '#ff4444', fontSize: 12, marginBottom: 12, padding: '8px 12px', background: '#1a0000', borderRadius: 4 },
  infoBox: { fontSize: 12, color: '#888', background: '#111', padding: '10px 14px', borderRadius: 4, marginBottom: 12, lineHeight: 1.5 },
  grid2: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 },
  field: {},
  sessionHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  sessionId: { fontSize: 12, color: '#666', marginRight: 8 },
  statusBadge: { fontSize: 10, padding: '2px 8px', borderRadius: 10, color: '#000', fontWeight: 700 },
  wafBadge: { marginLeft: 8, fontSize: 10, color: '#ff8800', background: '#1a0c00', padding: '2px 8px', borderRadius: 4 },
  wafBypassed: { marginLeft: 6, fontSize: 9, color: '#ff8800', background: '#1a0c00', padding: '1px 4px', borderRadius: 3 },
  statsRow: { display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' },
  statCard: { flex: 1, minWidth: 80, background: '#111', border: '1px solid #222', borderRadius: 4, padding: '10px 14px', textAlign: 'center' },
  statVal: { fontSize: 22, fontWeight: 700 },
  statLabel: { fontSize: 10, color: '#555', marginTop: 2 },
  chainBox: { background: '#0a0a14', border: '1px solid #1a1a33', borderRadius: 4, padding: 12, marginBottom: 16 },
  chainEntry: { fontSize: 11, color: '#5577ff', padding: '2px 0', borderBottom: '1px solid #111' },
  sectionTitle: { fontSize: 12, color: '#888', fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 },
  findingsList: { display: 'flex', flexDirection: 'column', gap: 8 },
  findingCard: { background: '#111', borderRadius: 4, padding: '10px 14px', cursor: 'pointer', transition: 'background 0.1s' },
  findingHeader: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 },
  findingTitle: { fontSize: 13, fontWeight: 600 },
  findingUrl: { fontSize: 11, color: '#555', wordBreak: 'break-all' },
  findingDetail: { marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 },
  detailLabel: { color: '#666', marginRight: 4 },
  code: { background: '#1a1a00', color: '#ffff00', padding: '2px 6px', borderRadius: 3, fontSize: 11, wordBreak: 'break-all' },
  evidence: { color: '#ff8800' },
  remediation: { color: '#88ff88' },
  detailMeta: { color: '#444', fontSize: 11, marginTop: 4 },
  empty: { color: '#444', fontSize: 13, padding: '20px 0', textAlign: 'center' },
  sessionRow: { background: '#111', border: '1px solid #222', borderRadius: 4, padding: '10px 14px', marginBottom: 8, cursor: 'pointer' },
  sessionMeta: { fontSize: 11, color: '#555', marginTop: 4 },
};
