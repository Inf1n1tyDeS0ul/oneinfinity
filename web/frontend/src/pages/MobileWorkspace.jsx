import React, { useState, useEffect, useRef } from 'react';
import {
  Smartphone, Upload, Shield, Zap, RefreshCw, Layers, History,
  Activity, Search, Cpu, Lock, Terminal, Network, Unlock,
  ChevronRight, Bug, AlertTriangle, CheckCircle, XCircle, Code, Eye, Play, Globe, Maximize2, Minimize2,
  PanelRightClose, PanelRightOpen, ChevronLeft, ChevronDown
} from 'lucide-react';
import api, { endpoints } from '../utils/api';
import { useStore } from '../store/useStore';
import { relativeTime } from '../utils/time';
import clsx from 'clsx';
import MobileXRayHUD from '../components/mobile/MobileXRayHUD';
import MobileReportViewer from '../components/mobile/MobileReportViewer';
import PackageList from '../components/mobile/PackageList';
import FridaScriptEditor from '../components/mobile/FridaScriptEditor';
import InterceptProxy from '../components/mobile/InterceptProxy';
import TrafficViewer from '../components/TrafficViewer';
import SSLBypassPanel from '../components/mobile/SSLBypassPanel';
import MobileSitemap from '../components/mobile/MobileSitemap';
import RewriteRulePanel from '../components/mobile/RewriteRulePanel';
import BreakpointPanel from '../components/mobile/BreakpointPanel';
import AttackLauncher from '../components/AttackLauncher';

// ── Command Nexus: docked side panel with tabs (replaces stacked panels) ──────
// Prevents overlap by giving each tool its own tab slot. Collapsible to free space.
const NEXUS_TABS = [
  { id: 'bypass',     label: 'Bypass',     icon: Unlock,   color: 'text-cyan-400',    border: 'border-cyan-500',    bg: 'bg-cyan-500/5' },
  { id: 'intercept',  label: 'Intercept',  icon: Eye,      color: 'text-emerald-400', border: 'border-emerald-500', bg: 'bg-emerald-500/5' },
  { id: 'breakpoints',label: 'Breakpts',   icon: Bug,      color: 'text-orange-400',  border: 'border-orange-500',  bg: 'bg-orange-500/5' },
  { id: 'rewrites',   label: 'Rewrites',   icon: Code,     color: 'text-purple-400',  border: 'border-purple-500',  bg: 'bg-purple-500/5' },
];

function CommandNexus({ appId, packageName, deviceId, collapsed, onToggleCollapse }) {
  const [activeNexusTab, setActiveNexusTab] = useState('bypass');
  const activeTabMeta = NEXUS_TABS.find(t => t.id === activeNexusTab) || NEXUS_TABS[0];

  return (
    <div className={clsx(
      "flex flex-col shrink-0 transition-all duration-300 ease-in-out overflow-hidden",
      "glass-card p-0 border-l border-bg-border",
      collapsed ? "w-10" : "w-96"
    )}>
      {/* Collapse strip — always visible */}
      <div className={clsx(
        "flex items-center border-b border-bg-border",
        collapsed ? "flex-col py-3 gap-3" : "flex-row px-3 py-2 gap-2"
      )}>
        <button
          onClick={onToggleCollapse}
          className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-400 hover:text-white hover:border-white/30 transition-all"
          title={collapsed ? "Expand Command Nexus" : "Collapse Command Nexus"}
        >
          {collapsed ? <PanelRightOpen size={12} /> : <PanelRightClose size={12} />}
        </button>

        {collapsed ? (
          /* Vertical icon strip when collapsed */
          NEXUS_TABS.map(t => (
            <button
              key={t.id}
              onClick={() => { setActiveNexusTab(t.id); onToggleCollapse(); }}
              title={t.label}
              className={clsx("p-1.5 rounded-lg transition-all", activeNexusTab === t.id ? "bg-white/10" : "hover:bg-white/5", t.color)}
            >
              <t.icon size={12} />
            </button>
          ))
        ) : (
          /* Horizontal tab strip when expanded */
          <>
            <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest mr-1">Nexus</span>
            {NEXUS_TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setActiveNexusTab(t.id)}
                className={clsx(
                  "flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[9px] font-black uppercase transition-all",
                  activeNexusTab === t.id
                    ? `${t.color} bg-white/10 border border-white/10`
                    : "text-slate-600 hover:text-slate-400"
                )}
              >
                <t.icon size={10} />
                {t.label}
              </button>
            ))}
          </>
        )}
      </div>

      {/* Panel body — hidden when collapsed */}
      {!collapsed && (
        <div className={clsx(
          "flex-1 overflow-hidden flex flex-col border-t-2",
          activeTabMeta.border
        )}>
          <div className={clsx("px-3 py-2 border-b border-bg-border flex items-center gap-2", activeTabMeta.bg)}>
            <activeTabMeta.icon size={11} className={activeTabMeta.color} />
            <span className={clsx("text-[9px] font-black uppercase tracking-widest", activeTabMeta.color)}>
              {activeTabMeta.label === 'Bypass' ? 'Security Bypass Hub'
                : activeTabMeta.label === 'Intercept' ? 'Live Intercept HUD'
                : activeTabMeta.label === 'Breakpts' ? 'Breakpoint Manager'
                : 'Rewrite Rules'}
            </span>
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {activeNexusTab === 'bypass' && (
              <div className="p-3">
                <SSLBypassPanelCompact appId={appId} packageName={packageName} deviceId={deviceId} />
              </div>
            )}
            {activeNexusTab === 'intercept' && (
              <div className="h-full min-h-[500px]">
                <InterceptProxy deviceId={deviceId} />
              </div>
            )}
            {activeNexusTab === 'breakpoints' && (
              <div className="p-3">
                <BreakpointPanel deviceId={deviceId} />
              </div>
            )}
            {activeNexusTab === 'rewrites' && (
              <div className="p-3">
                <RewriteRulePanel deviceId={deviceId} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── SSLBypassPanel compact wrapper ─────────────────────────────────────────────
// The original SSLBypassPanel renders a full 2-col layout not suitable for a
// narrow dock panel. This wrapper shows a compact action-first view.
function SSLBypassPanelCompact({ appId, packageName, deviceId }) {
  const { addNotification } = useStore();
  const [selectedMethod, setSelectedMethod] = useState('frida_universal');
  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState(null);

  const METHODS = [
    { id: 'frida_universal', label: 'Frida Universal', badge: 'RECOMMENDED', color: 'text-cyan-400' },
    { id: 'objection',       label: 'Objection',       badge: null,          color: 'text-slate-400' },
  ];

  const handleBypass = async () => {
    setExecuting(true);
    setResult(null);
    try {
      const response = await endpoints.mobileBypassSSL(appId, { method: selectedMethod, device_id: deviceId || '' });
      setResult(response.data);
      addNotification(response.data.success ? `SSL bypass: ${selectedMethod}` : 'SSL bypass failed', response.data.success ? 'success' : 'error');
    } catch (error) {
      addNotification(error.response?.data?.detail || 'Bypass failed', 'error');
      setResult({ success: false, error: error.message });
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="space-y-3">
      {/* Package indicator */}
      {packageName && (
        <div className="px-2 py-1.5 rounded bg-black/40 border border-white/5 font-mono text-[9px] text-slate-500 truncate">
          {packageName}
        </div>
      )}

      {/* Method selector — compact radio pills */}
      <div className="space-y-1.5">
        {METHODS.map(m => (
          <button
            key={m.id}
            onClick={() => setSelectedMethod(m.id)}
            className={clsx(
              "w-full text-left px-3 py-2 rounded-lg border transition-all flex items-center gap-2",
              selectedMethod === m.id
                ? "bg-accent-primary/10 border-accent-primary/30"
                : "bg-black/20 border-white/5 hover:border-white/10"
            )}
          >
            <div className={clsx("w-2 h-2 rounded-full border-2 flex-shrink-0 transition-all",
              selectedMethod === m.id ? "border-accent-primary bg-accent-primary" : "border-slate-700 bg-transparent"
            )} />
            <span className={clsx("text-[10px] font-bold flex-1", selectedMethod === m.id ? "text-slate-100" : "text-slate-500")}>
              {m.label}
            </span>
            {m.badge && (
              <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-[8px] font-black uppercase">{m.badge}</span>
            )}
          </button>
        ))}
      </div>

      {/* Execute button */}
      <button
        onClick={handleBypass}
        disabled={executing || !appId}
        className={clsx(
          "w-full flex items-center justify-center gap-2 py-2.5 rounded-lg border text-[10px] font-black uppercase transition-all",
          executing
            ? "bg-slate-700/20 border-slate-700 text-slate-600 cursor-not-allowed"
            : !appId
            ? "bg-slate-800/20 border-slate-800 text-slate-700 cursor-not-allowed"
            : "bg-cyan-500/10 border-cyan-500/30 hover:bg-cyan-500/20 text-cyan-400"
        )}
      >
        {executing ? <RefreshCw size={11} className="animate-spin" /> : <Zap size={11} />}
        {executing ? 'Injecting…' : !appId ? 'No App Selected' : 'Execute Bypass'}
      </button>

      {/* Result */}
      {result && (
        <div className={clsx(
          "flex items-start gap-2 p-2.5 rounded-lg border text-[10px]",
          result.success
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        )}>
          {result.success ? <CheckCircle size={12} className="mt-0.5 flex-shrink-0" /> : <XCircle size={12} className="mt-0.5 flex-shrink-0" />}
          <span>{result.success ? 'SSL validation disabled — traffic visible' : (result.message || result.error || 'Bypass failed')}</span>
        </div>
      )}

      {/* Technique info */}
      <div className="px-3 py-2.5 rounded-lg bg-black/30 border border-white/5 space-y-1">
        <div className="text-[9px] font-black text-slate-600 uppercase tracking-wider mb-1.5">Technique</div>
        {['Hook TrustManagerImpl', 'Patch OkHttp3 CertificatePinner', 'Override SSLContext', 'Intercept HTTPS via mitmproxy'].map((step, i) => (
          <div key={i} className="flex items-center gap-2 text-[9px] text-slate-600">
            <span className="text-accent-primary">{i + 1}.</span>
            <span>{step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Shared Sub-Components ───────────────────────────────────────────────────

function SetupPanel() {
  const apiBase = import.meta.env.VITE_API_BASE_URL || window.location.origin.replace('3000', '8000');
  const [lanUrl, setLanUrl] = useState(apiBase);

  useEffect(() => {
    api.get('/setup/ip').then(r => {
      setLanUrl(`http://${r.data.ip}:${r.data.port}`);
    }).catch(() => {});
  }, []);
  
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in duration-500">
      <div className="glass-card p-6 flex flex-col items-center text-center">
        <h3 className="text-sm font-black uppercase text-accent-primary mb-4">📱 QR Setup</h3>
        <div className="bg-white p-2 rounded-xl mb-4">
          <img src={`${apiBase}/api/setup/qr`} alt="Setup QR" className="w-32 h-32" />
        </div>
        <p className="text-[10px] text-slate-500 leading-relaxed">Scan with OneInfinity Companion app to link this workstation instantly.</p>
      </div>
      
      <div className="glass-card p-6">
        <h3 className="text-sm font-black uppercase text-accent-primary mb-4 text-center">🔍 Auto-Discovery</h3>
        <div className="space-y-3">
          <div className="p-3 bg-black/40 border border-white/5 rounded-lg text-[10px] text-slate-400 leading-relaxed">
            1. Connect device to same WiFi<br/>
            2. Open app → Tap "Auto-Discover"<br/>
            3. Backend found via mDNS/Bonjour<br/>
            <span className="text-[8px] text-orange-500 mt-2 block italic">Note: Requires 'zeroconf' python package on host</span>
          </div>
        </div>
      </div>

      <div className="glass-card p-6">
        <h3 className="text-sm font-black uppercase text-accent-primary mb-4 text-center">✍️ Manual Link</h3>
        <code className="block bg-black/60 p-3 rounded-lg text-[10px] font-mono text-cyan-400 border border-cyan-500/20 mb-4 break-all">
          {lanUrl}
        </code>
        <button 
          onClick={() => { navigator.clipboard.writeText(lanUrl); alert('Copied LAN URL!'); }}
          className="w-full py-2 bg-accent-primary/10 border border-accent-primary/20 rounded-lg text-[10px] font-black uppercase text-accent-primary hover:bg-accent-primary hover:text-black transition-all"
        >
          Copy LAN URL
        </button>
      </div>
    </div>
  );
}

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

function AppInspectorPanel({ deviceId }) {
  const [packageName, setPackageName] = useState('');
  const [appInfo, setAppInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  const inspectApp = async () => {
    if (!packageName.trim()) return;
    setLoading(true);
    try {
      const r = await api.get(`/mobile/agent/app_info/${deviceId}?package_name=${packageName}`);
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
        </div>
      )}
    </div>
  );
}

import './MobileAgent.css';

function DeviceControlPanel({ deviceId }) {
  const [loading, setLoading] = useState(false);
  const { addNotification } = useStore();

  const sendCommand = async (type, params = {}) => {
    setLoading(true);
    try {
      await endpoints.mobileCommand(deviceId, { type, ...params });
      addNotification(`Command ${type} sent`, 'success');
    } catch (e) { addNotification(e.message, 'error'); }
    finally { setLoading(false); }
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 animate-in fade-in duration-500">
      <ControlButton 
        label="Start Capture" 
        icon={Zap} 
        color="text-accent-primary" 
        onClick={() => sendCommand('start_capture')}
        disabled={loading}
      />
      <ControlButton 
        label="Stop Capture" 
        icon={XCircle} 
        color="text-red-500" 
        onClick={() => sendCommand('stop_capture')}
        disabled={loading}
      />
      <ControlButton 
        label="Install CA Cert" 
        icon={Shield} 
        color="text-cyan-400" 
        onClick={() => api.post('/mobile/mitm/install_cert', { device_id: deviceId })}
        disabled={loading}
      />
      <ControlButton 
        label="Push eBPF" 
        icon={Cpu} 
        color="text-purple-400" 
        onClick={() => api.post('/mobile/ebpf/push', { device_id: deviceId })}
        disabled={loading}
      />
      <ControlButton 
        label="Clear Cache" 
        icon={RefreshCw} 
        color="text-orange-400" 
        onClick={() => sendCommand('clear_cache')}
        disabled={loading}
      />
      <ControlButton 
        label="Dump Logcat" 
        icon={Terminal} 
        color="text-slate-400" 
        onClick={() => sendCommand('dump_logs')}
        disabled={loading}
      />
    </div>
  );
}

function ControlButton({ label, icon: Icon, color, onClick, disabled }) {
  return (
    <button 
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        "glass-card p-4 flex flex-col items-center gap-3 transition-all hover:scale-[1.02] active:scale-95 group",
        disabled ? "opacity-50 grayscale cursor-not-allowed" : "hover:border-white/20"
      )}
    >
      <div className={clsx("p-2 rounded-xl bg-white/5 border border-white/5 group-hover:bg-white/10 transition-colors", color)}>
        <Icon size={20} />
      </div>
      <span className="text-[9px] font-black uppercase text-slate-400 group-hover:text-slate-200">{label}</span>
    </button>
  );
}

// ── Unified Mobile Workspace ────────────────────────────────────────────────
// Merges static analysis and dynamic agent into a single high-performance IDE.

export default function MobileWorkspace() {
  const { addNotification } = useStore();
  
  // Selection State
  const [appId, setAppId] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('research'); // research | execution | correlation | report
  const [subTab, setSubTab] = useState('overview');
  const [jumpToFile, setJumpToFile] = useState(null);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const [workbenchExpanded, setWorkbenchExpanded] = useState(false);
  const [nexusCollapsed, setNexusCollapsed] = useState(false);

  const jumpToTab = (tab, sub = 'overview', file = null) => {
    setActiveTab(tab);
    setSubTab(sub);
    if (file) setJumpToFile(file);
  };

  const jumpToSource = (entry) => {
    // Basic heuristic: try to find endpoint in report that matches URL
    const url = entry.request?.url || '';
    const endpoint = report?.api_discovery?.endpoints?.find(ep => 
      url.includes(ep.url || ep.path)
    );

    if (endpoint?.file) {
      jumpToTab('research', 'source', endpoint.file);
      addNotification(`Jumping to source: ${endpoint.file}`, 'info');
    } else {
      addNotification('No direct code mapping found for this URL', 'warn');
      jumpToTab('research', 'source');
    }
  };

  // Async State
  const [history, setHistory] = useState([]);
  const [devices, setDevices] = useState([]);
  const [packages, setPackages] = useState([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [activePhase, setActivePhase] = useState('idle');
  const [selectedFileArtifact, setSelectedFileArtifact] = useState(null);
  const [uploadPct, setUploadPct] = useState(0);

  // Sidebar Ref
  const pollRef = useRef(null);

  const [capturedTraffic, setCapturedTraffic] = useState([]);

  const [useMobsf, setUseMobsf] = useState(false);
  const [mobsfAvailable, setMobsfAvailable] = useState(null);

  // ── Loaders ───────────────────────────────────────────────────────────────

  const loadData = async () => {
    try {
      const [hRes, dRes, mRes] = await Promise.all([
        endpoints.mobileApps(),
        api.get('/mobile/agent/list'),
        endpoints.mobileMobsfStatus().catch(() => ({ data: { available: false } }))
      ]);
      setHistory(Array.isArray(hRes.data) ? hRes.data : (hRes.data?.apps || []));
      setDevices(dRes.data || []);
      setMobsfAvailable(mRes.data?.available);
    } catch (e) { console.error('Failed to load workspace data', e); }
  };

  useEffect(() => {
    if (!selectedDevice) {
      setCapturedTraffic([]);
      return;
    }
    const fetchTraffic = async () => {
      try {
        const resp = await api.get(`/mobile/agent/traffic/${selectedDevice}?limit=100`);
        setCapturedTraffic(resp.data || []);
      } catch {}
    };
    fetchTraffic();
    const interval = setInterval(fetchTraffic, 3000);
    return () => clearInterval(interval);
  }, [selectedDevice]);

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 10000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      endpoints.devicePackages(selectedDevice).then(r => setPackages(r.data || [])).catch(() => {});
    }
  }, [selectedDevice]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const startAnalysisPoll = (id) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const scanRes = await endpoints.scans().catch(() => null)
        const scans = scanRes?.data || []
        const scanEntry = (Array.isArray(scans) ? scans : []).find(s => s.scan_id === `mobile_${id}`)
        
        if (scanEntry) {
          const pct = scanEntry.progress || 0
          const phase = scanEntry.current_phase || 'scanning'
          if (pct > 0) { setProgress(pct); setActivePhase(phase); }
          if (scanEntry.status === 'completed' || scanEntry.status === 'failed') {
            const r = await endpoints.mobileFullReport(id)
            setProgress(100); setActivePhase('completed');
            setReport(r.data || {});
            clearInterval(pollRef.current);
            setAnalyzing(false);
            addNotification(scanEntry.status === 'completed' ? 'Mobile analysis complete' : 'Analysis failed', scanEntry.status === 'completed' ? 'success' : 'error')
            loadData();
            return
          }
        }
        // Fallback progress logic
        const r = await endpoints.mobileFullReport(id)
        if (r.data?.static_analysis && progress < 50) { setActivePhase('ai'); setProgress(55); }
      } catch (err) { console.error('Report poll failed', err) }
    }, 5000)
  }

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFileArtifact) return addNotification('Select an APK/IPA file first', 'error');
    setAnalyzing(true); setReport(null); setUploadPct(0); setActivePhase('binary'); setProgress(5);
    setActiveTab('research'); // Switch to research to see HUD

    try {
      const formData = new FormData();
      formData.append('file', selectedFileArtifact);
      const res = await endpoints.mobileUpload(formData, (evt) => {
        if (evt.total) {
          const pct = Math.round((evt.loaded / evt.total) * 100);
          setUploadPct(pct);
          setProgress(Math.min(20, Math.floor(pct / 5)));
        }
      });
      const id = res.data.app_id;
      setAppId(id);
      await endpoints.mobileAnalyze(id, { run_dynamic: true, device_id: selectedDevice, run_api_attack: true, run_mobsf: useMobsf });
      setActivePhase('static'); setProgress(30);
      startAnalysisPoll(id);
    } catch (err) {
      addNotification(`Upload failed: ${err.message}`, 'error');
      setAnalyzing(false); setActivePhase('idle'); setProgress(0);
    }
  }

  const startAnalysis = async (pkgName) => {
    if (!selectedDevice) return addNotification('Select a device first', 'error');
    setAnalyzing(true); setReport(null); setActivePhase('ingest'); setProgress(10);
    setActiveTab('research'); // Switch to research to see HUD

    try {
      const res = await endpoints.packageIngest(selectedDevice, pkgName);
      const id = res.data.app_id;
      setAppId(id);
      await endpoints.mobileAnalyze(id, { run_dynamic: true, device_id: selectedDevice, run_api_attack: true, run_mobsf: useMobsf });
      setActivePhase('static'); setProgress(30);
      startAnalysisPoll(id);
    } catch (e) { addNotification(e.message, 'error'); setAnalyzing(false); }
  };

  const selectApp = async (app) => {
    setAppId(app.id);
    setAnalyzing(true);
    try {
      const r = await endpoints.mobileFullReport(app.id);
      setReport(r.data);
    } catch (e) { addNotification('Failed to load report', 'error'); }
    finally { setAnalyzing(false); }
  };

  // ── Styles ────────────────────────────────────────────────────────────────

  const s = {
    workspace: "flex h-[calc(100vh-64px)] overflow-hidden bg-bg-primary font-sans",
    sidebar: "w-72 bg-bg-secondary/50 border-r border-bg-border flex flex-col shrink-0",
    content: "flex-1 flex flex-col overflow-hidden",
    header: "h-16 border-b border-bg-border flex items-center justify-between px-6 bg-bg-primary/80 backdrop-blur-md",
    tabBar: "flex gap-1 p-1 bg-bg-secondary/40 rounded-xl border border-bg-border",
    tab: "px-4 py-1.5 rounded-lg text-[10px] font-black uppercase transition-all duration-300",
    tabActive: "bg-bg-elevated text-accent-primary border border-slate-700/50 shadow-glow-cyan/5",
    tabInactive: "text-slate-500 hover:text-slate-300"
  };

  return (
    <div className={s.workspace}>
      {/* ── Sidebar ── */}
      <aside className={s.sidebar}>
        <div className="p-5 border-b border-bg-border overflow-hidden">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
            <Layers size={12} className="text-accent-primary" /> Workspace Assets
          </h3>
          
          <div className="space-y-4">
            {/* Deploy Artifact (Restored) */}
            <form onSubmit={handleUpload} className="space-y-3">
              <div className="group border border-dashed border-bg-border rounded-xl p-4 text-center hover:border-accent-primary/50 transition-all cursor-pointer relative bg-bg-primary/20">
                <input type="file" onChange={e => setSelectedFileArtifact(e.target.files[0])} className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" />
                <div className="relative z-0">
                  <Upload size={14} className={clsx("mx-auto mb-2", selectedFileArtifact ? "text-accent-primary" : "text-slate-600")} />
                  <div className="text-[9px] font-bold text-slate-400 truncate">
                    {selectedFileArtifact ? selectedFileArtifact.name : 'DROP APK/IPA'}
                  </div>
                </div>
              </div>
              
              {mobsfAvailable && (
                <div 
                  className={clsx(
                    "flex items-center justify-between p-2 rounded-lg border transition-all cursor-pointer",
                    useMobsf ? "bg-accent-primary/10 border-accent-primary/30" : "bg-black/20 border-white/5"
                  )}
                  onClick={() => setUseMobsf(!useMobsf)}
                >
                  <span className="text-[8px] font-black text-slate-400 uppercase">Deep MobSF Scan</span>
                  <div className={clsx("w-6 h-3 rounded-full relative transition-all", useMobsf ? 'bg-accent-primary' : 'bg-slate-800')}>
                    <div className={clsx("absolute top-0.5 w-2 h-2 rounded-full bg-white transition-all", useMobsf ? 'left-3.5' : 'left-0.5')} />
                  </div>
                </div>
              )}

              <button type="submit" disabled={analyzing || !selectedFileArtifact} className="w-full py-2 bg-accent-primary text-black text-[10px] font-black uppercase rounded-lg shadow-glow-cyan disabled:opacity-50">
                {analyzing ? 'Engaging...' : 'Engage Analysis'}
              </button>
            </form>

            <div className="h-px bg-bg-border" />

            {/* Device Selector */}
            <div className="space-y-2">
              <label className="text-[9px] font-bold text-slate-600 uppercase tracking-tighter">Target Device</label>
              <select 
                className="w-full bg-black/40 border border-bg-border rounded-lg p-2 text-[11px] font-bold text-slate-300"
                value={selectedDevice || ''}
                onChange={e => setSelectedDevice(e.target.value)}
              >
                <option value="">No Device</option>
                {devices.map(d => <option key={d.device_id} value={d.device_id}>{d.model || d.device_id} ({d.online ? 'Online' : 'Offline'})</option>)}
              </select>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-none">
          <label className="text-[9px] font-bold text-slate-600 uppercase tracking-tighter px-1">Artifact History</label>
          {history.map(app => (
            <div 
              key={app.id} 
              onClick={() => selectApp(app)}
              className={clsx(
                "p-3 rounded-xl border transition-all cursor-pointer group",
                appId === app.id ? "border-accent-primary bg-accent-primary/5" : "border-slate-800 bg-bg-primary/20 hover:border-slate-700"
              )}
            >
              <div className="text-[10px] font-black text-slate-200 truncate group-hover:text-accent-primary">{app.filename || app.id}</div>
              <div className="flex justify-between items-center mt-2 text-[8px] font-mono text-slate-600 uppercase">
                <span>{app.platform}</span>
                <span>{relativeTime(app.uploaded_at)}</span>
              </div>
            </div>
          ))}
        </div>
      </aside>

      {/* ── Main Workspace ── */}
      <main className={s.content}>
        {/* Workspace Header */}
        <header className={s.header}>
          <div className="flex items-center gap-4">
            <div className="p-2 rounded-xl bg-accent-primary/10 border border-accent-primary/20">
              <Smartphone size={18} className="text-accent-primary" />
            </div>
            <div>
              <h2 className="text-sm font-black text-slate-100 uppercase tracking-tight">
                {report?.app_name || (appId ? 'Analyzing App...' : 'Select Artifact')}
              </h2>
              <div className="text-[10px] font-mono text-slate-500">
                {report?.package_name || 'WORKSPACE_IDLE'}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className={s.tabBar}>
              {[
                { id: 'agent',    label: 'Agent',    icon: Smartphone },
                { id: 'research', label: 'Research', icon: Search },
                { id: 'sitemap',  label: 'Sitemap',  icon: Globe },
                { id: 'execution',label: 'Execution', icon: Zap, badge: capturedTraffic.length },
                { id: 'correlation', label: 'Correlation', icon: Activity },
                { id: 'report',   label: 'Report',   icon: Shield },
              ].map(t => (
                <button 
                  key={t.id} 
                  onClick={() => setActiveTab(t.id)}
                  className={clsx(s.tab, activeTab === t.id ? s.tabActive : s.tabInactive, "relative")}
                >
                  <t.icon size={10} className="inline mr-1.5" />
                  {t.label}
                  {t.badge > 0 && (
                    <span className="absolute -top-1 -right-1 flex h-3 w-3 items-center justify-center rounded-full bg-red-500 text-[7px] font-black text-white shadow-glow-red">
                      {t.badge > 99 ? '99+' : t.badge}
                    </span>
                  )}
                </button>
              ))}
            </div>

            
            {report && (
              <div className="flex items-center gap-3 px-4 border-l border-bg-border ml-2">
                <div className="text-right">
                  <div className="text-[8px] font-black text-slate-500 uppercase">Risk</div>
                  <div className={clsx("text-lg font-black font-mono leading-none", 
                    report.risk_score > 7 ? 'text-red-500' : 'text-emerald-500'
                  )}>
                    {(report.risk_score || 0).toFixed(1)}
                  </div>
                </div>
              </div>
            )}
          </div>
        </header>

        {/* Workspace Body */}
        <div className="flex-1 overflow-y-auto p-6 scrollbar-thin">
          {activeTab === 'agent' && (
            <div className="max-w-6xl mx-auto space-y-8">
              <SetupPanel />
              
              <div className="glass-card p-6">
                <h3 className="text-sm font-black uppercase text-slate-100 mb-6 flex items-center gap-2">
                  <Smartphone size={16} className="text-accent-primary" /> Active Device Controls
                </h3>
                {selectedDevice ? (
                  <DeviceControlPanel deviceId={selectedDevice} />
                ) : (
                  <div className="py-12 text-center opacity-30">
                    <p className="text-xs font-black uppercase tracking-widest">Select a target device from the sidebar to enable controls</p>
                  </div>
                )}
              </div>

              {!appId && selectedDevice && !analyzing && (
                <div className="mt-8">
                  <PackageList 
                    packages={packages} 
                    onIngest={startAnalysis} 
                  />
                </div>
              )}
            </div>
          )}

          {!appId && !selectedDevice && activeTab !== 'agent' && (
            <div className="h-full flex flex-col items-center justify-center opacity-20 space-y-4">
              <Layers size={64} />
              <p className="text-sm font-black uppercase tracking-widest">Workspace Standby</p>
              <p className="text-[10px] font-mono">SELECT_ARTIFACT_OR_DEVICE_TO_BEGIN</p>
            </div>
          )}

          {!appId && selectedDevice && !analyzing && activeTab !== 'agent' && (
             <div className="max-w-5xl mx-auto">
                <PackageList 
                  packages={packages} 
                  onIngest={startAnalysis} 
                />
             </div>
          )}

          {analyzing && !report && (
             <div className="max-w-4xl mx-auto py-12">
                <MobileXRayHUD activePhase={activePhase} progress={progress} />
             </div>
          )}

          {activeTab === 'research' && report && (
            <MobileReportViewer 
              report={report} 
              appId={appId} 
              deviceId={selectedDevice} 
              initialTab={subTab} 
              initialFile={jumpToFile}
            />
          )}

          {activeTab === 'sitemap' && (
            <MobileSitemap 
              report={report} 
              deviceId={selectedDevice} 
              onNavigate={jumpToTab} 
            />
          )}

          {activeTab === 'execution' && (
            <div className="space-y-6">
              {/* Sub-tab bar — only show non-instrumentation tools; rewrites & breakpoints moved into Nexus */}
              <div className="flex gap-1 p-1 bg-bg-secondary/40 rounded-xl border border-bg-border w-fit mb-4">
                {['instrumentation', 'attacks', 'logs', 'inspector'].map(st => (
                  <button
                    key={st}
                    onClick={() => setSubTab(st)}
                    className={clsx(
                      "px-4 py-1.5 rounded-lg text-[9px] font-black uppercase transition-all",
                      subTab === st ? "bg-bg-elevated text-accent-primary" : "text-slate-500"
                    )}
                  >
                    {st}
                  </button>
                ))}
              </div>

              {subTab === 'instrumentation' && (
                <div className="flex flex-col gap-4 min-h-[700px] animate-in fade-in slide-in-from-bottom-2 duration-500">
                  {/* Top row: Workbench + Command Nexus side dock */}
                  <div className="flex gap-3 items-stretch" style={{ minHeight: 620 }}>
                    {/* Primary Workbench */}
                    <div className="flex-1 min-w-0 flex flex-col">
                      <div className="h-full glass-card p-0 overflow-hidden shadow-glow-purple/5 border-t-2 border-t-purple-500 flex flex-col">
                        <div className="bg-purple-500/5 px-4 py-2.5 border-b border-purple-500/20 flex items-center justify-between shrink-0">
                          <div className="flex items-center gap-3">
                            <Terminal size={12} className="text-purple-400" />
                            <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">
                              Dynamic Instrumentation Workbench
                            </span>
                          </div>
                          <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2">
                              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                              <span className="text-[9px] text-emerald-500 font-bold uppercase">Live</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex-1 bg-black/40 overflow-hidden">
                          <FridaScriptEditor appId={appId} packageName={report?.package_name} deviceId={selectedDevice} />
                        </div>
                      </div>
                    </div>

                    {/* Command Nexus — tabbed side dock, collapsible, never overlaps */}
                    <CommandNexus
                      appId={appId}
                      packageName={report?.package_name}
                      deviceId={selectedDevice}
                      collapsed={nexusCollapsed}
                      onToggleCollapse={() => setNexusCollapsed(v => !v)}
                    />
                  </div>

                  {/* Traffic Stream footer */}
                  <div className="glass-card p-0 overflow-hidden border-t-4 border-t-accent-primary shadow-glow-cyan/10 shrink-0">
                    <TrafficViewer deviceId={selectedDevice} onViewCode={jumpToSource} />
                  </div>
                </div>
              )}

              {subTab === 'attacks' && (
                <div className="glass-card p-0 overflow-hidden">
                  <AttackLauncher deviceId={selectedDevice} />
                </div>
              )}

              {subTab === 'logs' && (
                <div className="glass-card p-0 overflow-hidden">
                  <DeviceLogsPanel deviceId={selectedDevice} />
                </div>
              )}

              {subTab === 'inspector' && (
                <div className="glass-card p-0 overflow-hidden">
                  <AppInspectorPanel deviceId={selectedDevice} />
                </div>
              )}
            </div>
          )}

          {activeTab === 'correlation' && (
            <div className="h-full flex flex-col items-center justify-center py-20 glass-card bg-accent-primary/5 border-accent-primary/20 border-dashed">
               <Activity size={48} className="text-accent-primary mb-4" />
               <h3 className="text-lg font-black text-slate-100 uppercase mb-2">Semantic Execution Chains</h3>
               <p className="text-xs text-slate-400 max-w-md text-center leading-relaxed">
                  Correlation engine is active. Run instrumentation in the Execution tab to see 
                  real-time links between UI interactions, Frida events, and network triggers.
               </p>
               <button 
                 onClick={() => setActiveTab('execution')}
                 className="mt-6 px-6 py-2 bg-accent-primary text-black font-black uppercase text-[10px] rounded-lg shadow-glow-cyan"
               >
                 Start Instrumentation
               </button>
            </div>
          )}

          {activeTab === 'report' && report && (
            <div className="max-w-5xl mx-auto space-y-6">
               <div className="glass-card p-8 border-l-4 border-l-accent-primary">
                  <div className="flex justify-between items-start mb-8">
                     <div>
                        <h1 className="text-3xl font-black text-slate-100 tracking-tighter uppercase mb-2">Forensic Report</h1>
                        <p className="text-sm text-slate-500 font-mono">{report.package_name} · v{report.version || '1.0.0'}</p>
                     </div>
                     <div className="text-right">
                        <div className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1">Final Risk Rating</div>
                        <div className="text-5xl font-black text-accent-primary font-mono">{(report.risk_score || 0).toFixed(1)}</div>
                     </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-12">
                     <StatBox label="Total Findings" value={report.all_vulnerabilities?.length || 0} />
                     <StatBox label="Critical" value={report.severity_counts?.critical || 0} color="text-red-500" />
                     <StatBox label="High" value={report.severity_counts?.high || 0} color="text-orange-500" />
                     <StatBox label="Endpoints" value={report.api_discovery?.total_endpoints || 0} color="text-cyan-500" />
                  </div>
                  
                  <div className="space-y-4">
                     {report.all_vulnerabilities?.map((v, i) => (
                        <div key={i} className="p-4 bg-bg-secondary/40 border border-bg-border rounded-xl flex items-center justify-between group hover:border-slate-700 transition-all">
                           <div className="flex items-center gap-4">
                              <span className={clsx("w-2 h-2 rounded-full", v.severity === 'critical' ? 'bg-red-500 shadow-glow-red' : 'bg-orange-500 shadow-glow-orange')} />
                              <div>
                                 <div className="text-xs font-black text-slate-200 uppercase">{v.type || v.vulnerability}</div>
                                 <div className="text-[10px] text-slate-600 font-mono mt-0.5">{v.file || v.detail}</div>
                              </div>
                           </div>
                           <ChevronRight size={14} className="text-slate-700 group-hover:text-accent-primary" />
                        </div>
                     ))}
                  </div>
               </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function StatBox({ label, value, color = "text-slate-100" }) {
  return (
    <div className="p-4 rounded-2xl bg-bg-secondary/30 border border-bg-border">
      <div className="text-[8px] font-black text-slate-600 uppercase tracking-widest mb-2">{label}</div>
      <div className={clsx("text-2xl font-black font-mono", color)}>{value}</div>
    </div>
  )
}
