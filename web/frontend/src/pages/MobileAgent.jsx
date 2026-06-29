import React, { useState, useEffect } from 'react';
import api, { endpoints } from '../utils/api';
import TrafficViewer from '../components/TrafficViewer';
import AttackLauncher from '../components/AttackLauncher';
import FridaScriptEditor from '../components/mobile/FridaScriptEditor';
import RewriteRulePanel from '../components/mobile/RewriteRulePanel';
import BreakpointPanel from '../components/mobile/BreakpointPanel';
import InterceptProxy from '../components/mobile/InterceptProxy';

// ── iOS Suite Panel (Phase 4 inline component) ────────────────────────────

function IOSSuitePanel({ deviceId }) {
  const [correlations, setCorrelations] = React.useState([]);
  const [atsResult, setAtsResult] = React.useState(null);
  const [plistInput, setPlistInput] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    api.get('/mobile/ios/correlations')
      .then(r => setCorrelations(r.data)).catch(() => {});
  }, []);

  const analyzeATS = async () => {
    if (!plistInput.trim()) return;
    setLoading(true);
    try {
      const r = await api.post('/mobile/ios/ats/analyze', { plist_data: btoa(plistInput) });
      setAtsResult(r.data);
    } catch(e) { console.error(e); }
    setLoading(false);
  };

  const s = {
    container: { background: '#0a0a0a', color: '#ddd', fontFamily: 'monospace', padding: 16, borderRadius: 8 },
    header:    { fontSize: 16, fontWeight: 700, color: '#00aaff', marginBottom: 14 },
    section:   { background: '#111', border: '1px solid #222', borderRadius: 4, padding: 12, marginBottom: 12 },
    label:     { fontSize: 10, color: '#555', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'block' },
    textarea:  { width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: 10, fontSize: 11, borderRadius: 4, resize: 'vertical', minHeight: 120, fontFamily: 'monospace', boxSizing: 'border-box' },
    btn:       { padding: '8px 16px', border: '1px solid #0055aa', background: '#001133', borderRadius: 4, color: '#44aaff', cursor: 'pointer', fontSize: 12 },
    sevColor:  { critical: '#ff2244', high: '#ff6600', medium: '#ffaa00', low: '#44aaff', info: '#888' },
    badge:     { fontSize: 9, padding: '2px 5px', borderRadius: 3, marginRight: 4 },
  };

  return (
    <div style={s.container}>
      <div style={s.header}>🍎 iOS Security Suite</div>

      {/* Cross-platform correlations */}
      <div style={s.section}>
        <label style={s.label}>⚡ Cross-Platform Correlations ({correlations.length})</label>
        {correlations.length === 0 ? (
          <div style={{ fontSize: 11, color: '#444' }}>
            No correlated findings yet. Connect Android and iOS devices testing the same backend.
          </div>
        ) : correlations.map(c => (
          <div key={c.correlation_id} style={{ borderLeft: `3px solid ${s.sevColor[c.escalated_severity] || '#888'}`, paddingLeft: 8, marginBottom: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 700 }}>
              <span style={{ color: s.sevColor[c.escalated_severity] }}>[{c.escalated_severity?.toUpperCase()}]</span>{' '}
              {c.vuln_type?.toUpperCase()} on {c.backend_host}
            </div>
            <div style={{ fontSize: 10, color: '#666' }}>
              Confirmed: {c.platforms_confirmed?.join(' + ')} · Confidence: {((c.confidence||0)*100).toFixed(0)}%
            </div>
          </div>
        ))}
      </div>

      {/* ATS Analyzer */}
      <div style={s.section}>
        <label style={s.label}>🛡 ATS Analyzer — Paste Info.plist content</label>
        <textarea value={plistInput} onChange={e => setPlistInput(e.target.value)}
          placeholder={'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist ...>\n<plist version="1.0">\n<dict>\n  ...\n</dict>\n</plist>'}
          style={s.textarea} />
        <button onClick={analyzeATS} disabled={loading} style={{ ...s.btn, marginTop: 8 }}>
          {loading ? 'Analyzing…' : 'Analyze ATS'}
        </button>
        {atsResult && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, color: '#888', marginBottom: 6 }}>
              {atsResult.total_findings} finding(s) · {atsResult.url_schemes?.length || 0} URL scheme(s)
            </div>
            {(atsResult.ats_findings || []).map((f, i) => (
              <div key={i} style={{ borderLeft: `3px solid ${s.sevColor[f.severity]||'#888'}`, paddingLeft: 8, marginBottom: 6, fontSize: 11 }}>
                <div style={{ color: s.sevColor[f.severity] }}>[{f.severity?.toUpperCase()}]</div>
                <div>{f.issue}</div>
                <div style={{ color: '#555', fontSize: 10 }}>{f.mastg_id}</div>
              </div>
            ))}
            {(atsResult.url_schemes || []).length > 0 && (
              <div style={{ fontSize: 11, marginTop: 8 }}>
                <span style={{ color: '#888' }}>URL schemes: </span>
                {atsResult.url_schemes.map(s => (
                  <span key={s} style={{ background: '#001133', color: '#44aaff', padding: '1px 5px', borderRadius: 3, marginRight: 4, fontSize: 10 }}>{s}://</span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div style={s.section}>
        <label style={s.label}>📋 iOS Companion Setup</label>
        <div style={{ fontSize: 11, color: '#666', lineHeight: 1.6 }}>
          1. Build ios-companion/ in Xcode with Network Extension entitlement<br/>
          2. Install on iOS device (jailbreak optional)<br/>
          3. Open app → QR scan or enter backend URL<br/>
          4. Grant VPN permission for traffic capture<br/>
          5. For Frida: install frida-server from build.frida.re via Cydia
        </div>
      </div>
    </div>
  );
}

// ── Device Logs Panel ─────────────────────────────────────────────────────

function DeviceLogsPanel({ deviceId }) {
  const [logs, setLogs] = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const logEndRef = React.useRef(null);

  useEffect(() => {
    if (!deviceId) return;
    const fetchLogs = async () => {
      try {
        const r = await api.get(`/mobile/agent/logs/${deviceId}?limit=200`);
        setLogs(r.data || []);
      } catch {}
    };
    fetchLogs();
    const t = setInterval(fetchLogs, 2000);
    return () => clearInterval(t);
  }, [deviceId]);

  useEffect(() => {
    if (autoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  return (
    <div className="log-viewer-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: '#00ff88' }}>📜 Device Logs</span>
        <label style={{ fontSize: 10, color: '#666', display: 'flex', alignItems: 'center', gap: 4 }}>
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
          Auto-scroll
        </label>
      </div>
      <div className="log-list">
        {logs.length === 0 ? (
          <div style={{ color: '#333', textAlign: 'center', marginTop: 40 }}>Waiting for logs...</div>
        ) : logs.map((log, i) => (
          <div key={i} className="log-row">
            <span className="log-timestamp">{new Date(log.timestamp * 1000).toLocaleTimeString()}</span>
            <span className="log-tag">[{log.tag}]</span>
            <span className={`log-message ${log.level}`}>{log.message}</span>
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}

// ── App Inspector Panel ───────────────────────────────────────────────────

function AppInspectorPanel({ deviceId }) {
  const [packageName, setPackageName] = useState('');
  const [appInfo, setAppInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  const inspectApp = async () => {
    if (!packageName.trim()) return;
    setLoading(true);
    try {
      const r = await api.get(`/mobile/agent/app_info/${deviceId}?package_name=${packageName}`);
      // In this demo, we'll wait for the status update to populate device_metadata
      // But for immediate feedback, we'll show the "requested" status
      setAppInfo({ status: 'requested', package_name: packageName });
    } catch(e) { alert(e.message); }
    setLoading(false);
  };

  const styles = {
    section:   { background: '#111', border: '1px solid #222', borderRadius: 4, padding: 12, marginBottom: 12 },
    label:     { fontSize: 10, color: '#555', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'block' },
  };

  const s = styles;

  const getRecommendedBypasses = (pkg) => {
    const recommended = [];
    if (pkg.toLowerCase().includes('dexguard')) recommended.push('dexguard_bypass');
    if (pkg.toLowerCase().includes('sealing')) recommended.push('appsealing_bypass');
    if (pkg.toLowerCase().includes('arxan')) recommended.push('arxan_bypass');
    
    // Always recommend SSL and Root for testing
    recommended.push('ssl_bypass', 'root_bypass');
    return recommended;
  };

  return (
    <div className="app-inspector-panel">
      <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        <input 
          style={{ flex: 1, background: '#111', border: '1px solid #333', color: '#fff', padding: '8px 12px', borderRadius: 4, fontFamily: 'monospace' }}
          placeholder="com.example.app"
          value={packageName}
          onChange={e => setPackageName(e.target.value)}
        />
        <button 
          style={{ background: '#00ff88', color: '#000', border: 'none', padding: '8px 16px', borderRadius: 4, fontWeight: 'bold', cursor: 'pointer' }}
          onClick={inspectApp}
          disabled={loading}
        >
          {loading ? 'Requesting...' : 'Inspect App'}
        </button>
      </div>

      {appInfo && (
        <div className="app-details">
          <div className="app-meta-grid">
            <div className="meta-item">
              <span className="meta-label">Package Name</span>
              <span className="meta-value">{appInfo.package_name}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Status</span>
              <span className="meta-value" style={{ color: '#ffaa00' }}>{appInfo.status.toUpperCase()}</span>
            </div>
          </div>

          <div style={{ marginTop: 20 }}>
            <span style={{ fontSize: 10, color: '#555', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 10 }}>
              🛡 Recommended Bypasses
            </span>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {getRecommendedBypasses(appInfo.package_name).map(b => (
                <button key={b} onClick={() => alert(`Redirect to Frida Lab with ${b}?`)}
                  style={{ background: '#111', border: '1px solid #333', color: '#00ff88', padding: '5px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>
                  {b.replace('_', ' ').toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div style={{ background: '#111', padding: 12, borderRadius: 4, fontSize: 11, color: '#888', marginTop: 20 }}>
            💡 Metadata extraction takes 5-10s. Results will appear here once the device responds.
          </div>
        </div>
      )}
    </div>
  );
}

import './MobileAgent.css';

export default function MobileAgent() {
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [commandLog, setCommandLog] = useState([]);
  const [loading, setLoading] = useState(false);
  const [capturedTraffic, setCapturedTraffic] = useState([]);
  const [activeTab, setActiveTab] = useState('devices'); // devices | attack | frida | ios | rewrite | breakpoints

  useEffect(() => {
    // Poll for devices every 2 seconds
    const fetchDevices = async () => {
      try {
        const resp = await api.get('/mobile/agent/list');
        setDevices(resp.data || resp);
      } catch (err) {
        console.error('Failed to fetch devices:', err);
      }
    };

    fetchDevices();
    const interval = setInterval(fetchDevices, 2000);
    return () => clearInterval(interval);
  }, []);

  // Keep captured traffic in sync when a device is selected
  useEffect(() => {
    if (!selectedDevice) return;
    const fetchTraffic = async () => {
      try {
        const resp = await api.get(`/mobile/agent/traffic/${selectedDevice}?limit=500`);
        setCapturedTraffic(resp.data || resp || []);
      } catch {}
    };
    fetchTraffic();
    const interval = setInterval(fetchTraffic, 5000);
    return () => clearInterval(interval);
  }, [selectedDevice]);

  const sendCommand = async (cmd) => {
    if (!selectedDevice) return;

    setLoading(true);
    try {
      const resp = await api.post('/mobile/agent/command', {
        device_id: selectedDevice,
        ...cmd
      }, {
        params: { device_id: selectedDevice }
      });

      setCommandLog(prev => [
        ...prev,
        {
          timestamp: new Date().toISOString(),
          device: selectedDevice,
          command: cmd.type,
          status: resp.status || 'sent'
        }
      ]);
    } catch (err) {
      console.error('Failed to send command:', err);
      setCommandLog(prev => [
        ...prev,
        {
          timestamp: new Date().toISOString(),
          device: selectedDevice,
          command: cmd.type,
          status: 'error',
          error: err.message
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const formatUptime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}h ${minutes}m ${secs}s`;
  };

  const tabStyle = (t) => ({
    padding: '8px 20px',
    background: activeTab === t ? '#222' : '#111',
    border: `1px solid ${activeTab === t ? '#ff4444' : '#333'}`,
    borderRadius: 4,
    color: activeTab === t ? '#fff' : '#666',
    cursor: 'pointer',
    fontSize: 13,
    fontFamily: 'monospace',
  });

  return (
    <div className="mobile-agent-page">
      <div className="page-header">
        <h1>Mobile Companion</h1>
        <p>Device management, traffic capture, attack execution, and Frida instrumentation</p>
      </div>

      {/* Top-level tab nav */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        <button style={tabStyle('devices')} onClick={() => setActiveTab('devices')}>
          📱 Devices
        </button>
        <button style={tabStyle('intercept')} onClick={() => setActiveTab('intercept')}>
          🔍 Intercept Proxy
        </button>
        <button style={tabStyle('attack')} onClick={() => setActiveTab('attack')}>
          ⚡ Attack Launcher
          {capturedTraffic.length > 0 && (
            <span style={{ marginLeft: 6, fontSize: 10, background: '#cc1133', color: '#fff', padding: '1px 5px', borderRadius: 8 }}>
              {capturedTraffic.length}
            </span>
          )}
        </button>
        <button style={tabStyle('frida')} onClick={() => setActiveTab('frida')}>
          🔬 Frida Lab
        </button>
        <button style={tabStyle('ios')} onClick={() => setActiveTab('ios')}>
          🍎 iOS Suite
        </button>
        <button style={tabStyle('inspector')} onClick={() => setActiveTab('inspector')}>
          🕵️ App Inspector
        </button>
        <button style={tabStyle('logs')} onClick={() => setActiveTab('logs')}>
          📜 Logs
        </button>
        <button style={tabStyle('rewrite')} onClick={() => setActiveTab('rewrite')}>
          ⚙️ Rewrite Rules
        </button>
        <button style={tabStyle('breakpoints')} onClick={() => setActiveTab('breakpoints')}>
          ⏸ Breakpoints
        </button>
      </div>

      {/* Attack Launcher tab — Phase 2 */}
      {activeTab === 'attack' && (
        <AttackLauncher deviceId={selectedDevice} capturedTraffic={capturedTraffic} />
      )}

      {/* Frida Lab tab — Phase 3 */}
      {activeTab === 'frida' && (
        <FridaScriptEditor deviceId={selectedDevice} packageName="" appId="" />
      )}

      {/* iOS Suite tab — Phase 4 */}
      {activeTab === 'ios' && (
        <IOSSuitePanel deviceId={selectedDevice} />
      )}

      {/* App Inspector tab */}
      {activeTab === 'inspector' && (
        <AppInspectorPanel deviceId={selectedDevice} />
      )}

      {/* Logs tab */}
      {activeTab === 'logs' && (
        <DeviceLogsPanel deviceId={selectedDevice} />
      )}

      {/* Intercept Proxy tab — unified Burp-like UI */}
      {activeTab === 'intercept' && (
        <div style={{ height: 'calc(100vh - 220px)' }}>
          <InterceptProxy deviceId={selectedDevice} />
        </div>
      )}

      {/* Rewrite Rules tab */}
      {activeTab === 'rewrite' && (
        <RewriteRulePanel deviceId={selectedDevice} />
      )}

      {/* Breakpoints tab */}
      {activeTab === 'breakpoints' && (
        <BreakpointPanel deviceId={selectedDevice} />
      )}

      {activeTab === 'devices' && <><div className="setup-section">
        <h2>Setup Instructions</h2>
        <div className="setup-grid">
          <div className="setup-card">
            <h3>📱 QR Code Setup</h3>
            <p>Scan this QR code with OneInfinity Companion app:</p>
            <img
              src={`${import.meta.env.VITE_API_BASE_URL || window.location.origin.replace('3000', '8000')}/api/setup/qr`}
              alt="Setup QR Code"
              className="qr-code"
            />
          </div>
          <div className="setup-card">
            <h3>🔍 Auto-Discovery</h3>
            <p>Ensure your device is on the same WiFi network.</p>
            <p>Open the app and tap <strong>"Auto-Discover"</strong>.</p>
            <p>The app will find the backend automatically via mDNS.</p>
          </div>
          <div className="setup-card">
            <h3>✍️ Manual Setup</h3>
            <p>Enter this URL manually in the app:</p>
            <code className="backend-url">
              {import.meta.env.VITE_API_BASE_URL || window.location.origin.replace('3000', '8000')}
            </code>
            <button
              className="copy-btn"
              onClick={() => {
                const url = import.meta.env.VITE_API_BASE_URL || window.location.origin.replace('3000', '8000');
                navigator.clipboard.writeText(url);
                alert('URL copied to clipboard!');
              }}
            >
              Copy URL
            </button>
          </div>
        </div>
      </div>

      <div className="devices-section">
        <h2>Connected Devices ({devices.filter(d => d.online).length}/{devices.length})</h2>

        {devices.length === 0 ? (
          <div className="empty-state">
            <p>No devices registered yet. Follow setup instructions above.</p>
          </div>
        ) : (
          <div className="device-grid">
            {devices.map(d => (
              <div
                key={d.device_id}
                className={`device-card ${d.online ? 'online' : 'offline'} ${selectedDevice === d.device_id ? 'selected' : ''}`}
                onClick={() => d.online && setSelectedDevice(d.device_id)}
              >
                <div className="device-header">
                  <h3>{d.device_id}</h3>
                  <span className={`status-badge ${d.online ? 'online' : 'offline'}`}>
                    {d.online ? '🟢 Online' : '🔴 Offline'}
                  </span>
                </div>
                <div className="device-info">
                  <p><strong>Platform:</strong> {d.platform} {d.version}</p>
                  <p><strong>Root/Jailbreak:</strong> {d.root_status ? '✅ Yes' : '❌ No'}</p>
                  <p><strong>Capabilities:</strong> {d.capabilities?.join(', ') || 'N/A'}</p>
                  
                  {d.capture_status?.layers && (
                    <div className="layer-status-container">
                      {Object.entries(d.capture_status.layers).map(([name, layer]) => (
                        <span key={name} className={`layer-badge ${layer.running ? 'active' : ''}`}>
                          {name}
                        </span>
                      ))}
                    </div>
                  )}

                  {d.online && (
                    <p><strong>Uptime:</strong> {formatUptime(d.uptime || 0)}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedDevice && (
        <div className="control-panel">
          <h2>Control Panel: {selectedDevice}</h2>

          <div className="action-buttons">
            <button
              className="action-btn primary"
              onClick={() => setActiveTab('intercept')}
            >
              🔍 Open Intercept Proxy
            </button>
            <button
              className="action-btn secondary"
              onClick={() => api.post('/mobile/mitm/install_cert', { device_id: selectedDevice }).catch(() => {})}
              disabled={loading}
            >
              📜 Install CA Cert
            </button>
            <button
              className="action-btn secondary"
              onClick={() => api.post('/mobile/ebpf/push', { device_id: selectedDevice })
                .then(() => alert('✅ ecapture binary pushed to device'))
                .catch(e => alert('❌ Push failed: ' + e.message))}
              disabled={loading}
            >
              ⚡ Push eBPF Binary
            </button>
            <button
              className="action-btn primary"
              onClick={() => sendCommand({ type: 'start_capture' })}
              disabled={loading}
            >
              🎯 Start VPN Capture
            </button>
            <button
              className="action-btn secondary"
              onClick={() => sendCommand({ type: 'stop_capture' })}
              disabled={loading}
            >
              ⏸️ Stop VPN Capture
            </button>
            <button
              className="action-btn"
              onClick={() => sendCommand({ type: 'inject_payload', payload: '<script>alert(1)</script>' })}
              disabled={loading}
            >
              💉 Inject Test Payload
            </button>
            <button
              className="action-btn"
              onClick={() => sendCommand({ type: 'clear_cache' })}
              disabled={loading}
            >
              🗑️ Clear Cache
            </button>
          </div>

          <div className="command-log">
            <h3>Command Log</h3>
            {commandLog.length === 0 ? (
              <p className="empty-log">No commands sent yet</p>
            ) : (
              <div className="log-entries">
                {commandLog.slice().reverse().map((entry, idx) => (
                  <div key={idx} className={`log-entry ${entry.status}`}>
                    <span className="timestamp">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                    <span className="command">{entry.command}</span>
                    <span className="status">{entry.status}</span>
                    {entry.error && <span className="error">{entry.error}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>

          <TrafficViewer deviceId={selectedDevice} />
        </div>
      )}
      </>}
    </div>
  );
}
