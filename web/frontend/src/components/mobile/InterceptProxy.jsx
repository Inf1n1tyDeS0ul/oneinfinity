import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../../utils/api';

const SOURCE_COLORS = {
  mitm:        '#00ff88',
  frida_ssl:   '#00aaff',
  ebpf:        '#aa00ff',
  ebpf_tshark: '#cc44ff',
  tcpdump:     '#ffaa00',
  vpn:         '#ff8800',
  unknown:     '#555',
};
const SOURCE_LABELS = {
  mitm: 'MITM', frida_ssl: 'FRIDA', ebpf: 'eBPF',
  ebpf_tshark: 'eBPF+', tcpdump: 'TCPDUMP', vpn: 'VPN', unknown: '?',
};
const METHOD_COLORS = {
  GET:'#00ff88', POST:'#ff8800', PUT:'#00aaff',
  DELETE:'#ff4444', PATCH:'#ffaa00', CONNECT:'#888', SSL_write:'#aa00ff',
};
const LAYER_ICONS = { mitm:'🔓', frida_ssl:'🪝', ebpf:'⚡', tcpdump:'📡', vpn:'🔒' };

const s = {
  root:      { display:'flex', flexDirection:'column', height:'100%', background:'#080808', color:'#ddd', fontFamily:'monospace', fontSize:12 },
  toolbar:   { display:'flex', alignItems:'center', gap:8, padding:'8px 12px', background:'#111', borderBottom:'1px solid #222', flexWrap:'wrap' },
  statusBar: { display:'flex', gap:12, padding:'6px 12px', background:'#0a0a0a', borderBottom:'1px solid #1a1a1a', flexWrap:'wrap', alignItems:'center' },
  layerPill: (running, err) => ({ fontSize:10, padding:'2px 8px', borderRadius:10, background: running ? '#00ff8811' : err ? '#ff000011' : '#33333311', color: running ? '#00ff88' : err ? '#ff4444' : '#444', border:`1px solid ${running ? '#00ff8833' : err ? '#ff000033' : '#333'}` }),
  body:      { display:'flex', flex:1, overflow:'hidden' },
  left:      { width:'55%', overflowY:'auto', borderRight:'1px solid #1a1a1a' },
  right:     { flex:1, overflowY:'auto', padding:12 },
  tableHead: { display:'grid', gridTemplateColumns:'32px 60px 60px 1fr 60px 60px 50px', gap:4, padding:'6px 8px', background:'#111', borderBottom:'1px solid #1a1a2e', fontSize:10, color:'#555', fontWeight:700, textTransform:'uppercase', letterSpacing:0.5, position:'sticky', top:0, zIndex:1 },
  tableRow:  (sel) => ({ display:'grid', gridTemplateColumns:'32px 60px 60px 1fr 60px 60px 50px', gap:4, padding:'5px 8px', borderBottom:'1px solid #0d0d0d', cursor:'pointer', background: sel ? '#0a1a2e' : 'transparent', alignItems:'center' }),
  badge:     (c) => ({ fontSize:9, padding:'1px 5px', borderRadius:3, background:c+'22', color:c, fontWeight:700 }),
  decBadge:  (d) => ({ fontSize:9, padding:'1px 5px', borderRadius:3, background:d?'#00ff8822':'#55555522', color:d?'#00ff88':'#555' }),
  sectionHdr:{ fontSize:10, color:'#555', fontWeight:700, textTransform:'uppercase', letterSpacing:1, marginBottom:6, marginTop:12 },
  input:     { width:'100%', background:'#060606', border:'1px solid #222', color:'#ddd', padding:'5px 8px', fontSize:11, borderRadius:3, fontFamily:'monospace', boxSizing:'border-box' },
  textarea:  { width:'100%', background:'#060606', border:'1px solid #222', color:'#ddd', padding:'5px 8px', fontSize:11, borderRadius:3, fontFamily:'monospace', resize:'vertical', minHeight:120, boxSizing:'border-box' },
  btn:       (c) => ({ padding:'5px 14px', border:`1px solid ${c}44`, background:c+'11', color:c, borderRadius:3, cursor:'pointer', fontSize:11, marginRight:4, fontFamily:'monospace' }),
  pill:      (active, c) => ({ fontSize:10, padding:'3px 9px', borderRadius:10, cursor:'pointer', background:active?c+'33':'#11111100', color:active?c:'#444', border:`1px solid ${active?c+'66':'#222'}`, userSelect:'none' }),
  tab:       (a) => ({ padding:'6px 14px', cursor:'pointer', borderBottom:a?'2px solid #00aaff':'2px solid transparent', color:a?'#00aaff':'#555', fontSize:12, background:'transparent', border:'none', fontFamily:'monospace' }),
  interceptCard: { background:'#0f0f0f', border:'2px solid #ff8800', borderRadius:6, padding:12, marginBottom:8 },
  pre:       { background:'#060606', padding:10, borderRadius:4, overflow:'auto', maxHeight:200, fontSize:11, color:'#ccc', margin:0, whiteSpace:'pre-wrap' },
};

const WS_BASE = (import.meta.env.VITE_BACKEND_URL || 'http://localhost:47291').replace('http','ws');

export default function InterceptProxy({ deviceId }) {
  const [traffic, setTraffic]         = useState([]);
  const [selected, setSelected]       = useState(null);
  const [sourceFilter, setSrcFilter]  = useState('all');
  const [urlFilter, setUrlFilter]     = useState('');
  const [activeTab, setTab]           = useState('history');
  const [captureRunning, setRunning]  = useState(false);
  const [interceptOn, setIntercept]   = useState(false);
  const [sessionStatus, setStatus]    = useState(null);
  const [pending, setPending]         = useState([]);
  const [editBp, setEditBp]           = useState(null);
  const [editedBody, setEditedBody]   = useState('');
  const [repeaterReq, setRep]         = useState({ method:'GET', url:'', headers:'{}', body:'' });
  const [repeaterResp, setRepResp]    = useState(null);
  const [repHistory, setRepHistory]   = useState([]);
  const wsRef       = useRef(null);
  const pendingPoll = useRef(null);

  // ── WebSocket live traffic feed ─────────────────────────────────────────────
  useEffect(() => {
    if (!deviceId || !captureRunning) return;
    const ws = new WebSocket(`${WS_BASE}/ws/mobile/traffic/${deviceId}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'traffic_entry') {
          setTraffic(prev => [msg.entry, ...prev].slice(0, 500));
        }
      } catch {}
    };

    const ping = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 10000);

    return () => {
      clearInterval(ping);
      ws.close();
      wsRef.current = null;
    };
  }, [deviceId, captureRunning]);

  // ── Initial traffic load (history) ─────────────────────────────────────────
  useEffect(() => {
    if (!deviceId) return;
    const params = new URLSearchParams({ limit: 200 });
    if (sourceFilter !== 'all') params.set('source', sourceFilter);
    if (urlFilter) params.set('url_contains', urlFilter);
    api.get(`/mobile/agent/traffic/${deviceId}?${params}`)
       .then(r => setTraffic(r.data || [])).catch(() => {});
  }, [deviceId, sourceFilter, urlFilter]);

  // ── Status poll ─────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!deviceId) return;
    const poll = () => api.get(`/mobile/intercept/status/${deviceId}`)
      .then(r => { setStatus(r.data); setRunning(r.data?.status === 'running'); })
      .catch(() => {});
    poll();
    const t = setInterval(poll, 5000);
    return () => clearInterval(t);
  }, [deviceId]);

  // ── Pending intercepts poll ─────────────────────────────────────────────────
  useEffect(() => {
    if (!deviceId || !interceptOn) { setPending([]); return; }
    const poll = async () => {
      const [bp, mitm] = await Promise.all([
        api.get(`/mobile/breakpoint/pending/${deviceId}`).then(r=>r.data||[]).catch(()=>[]),
        api.get(`/mobile/mitm/intercept/pending/${deviceId}`).then(r=>r.data||[]).catch(()=>[]),
      ]);
      setPending([...bp, ...mitm]);
    };
    poll();
    pendingPoll.current = setInterval(poll, 800);
    return () => clearInterval(pendingPoll.current);
  }, [deviceId, interceptOn]);

  // ── Actions ─────────────────────────────────────────────────────────────────
  const startCapture = async () => {
    try {
      const r = await api.post('/mobile/intercept/start', { device_id: deviceId });
      setStatus(r.data);
      setRunning(true);
      setTraffic([]);
    } catch (e) { alert('Start failed: ' + e.message); }
  };

  const stopCapture = async () => {
    await api.post('/mobile/intercept/stop', { device_id: deviceId }).catch(() => {});
    setRunning(false);
    if (wsRef.current) wsRef.current.close();
  };

  const toggleIntercept = async () => {
    const next = !interceptOn;
    setIntercept(next);
    await api.post('/mobile/intercept/intercept_mode', { device_id: deviceId, enabled: next }).catch(() => {});
  };

  const releaseBp = async (bp, modified = false) => {
    const bpId = bp.breakpoint_id || bp.flow_id;
    const body = modified ? editedBody : '';
    if (bp.breakpoint_id) {
      await api.post(`/mobile/breakpoint/resume/${bpId}`, { modified_bytes: btoa(body) }).catch(()=>{});
    } else if (bp.flow_id) {
      await api.post(`/mobile/mitm/intercept/resume/${bpId}`, { modified: body||null }).catch(()=>{});
    }
    setEditBp(null);
    setPending(p => p.filter(x => (x.breakpoint_id||x.flow_id) !== bpId));
  };

  const sendToRepeater = (entry) => {
    const req = entry.request || {};
    setRep({ method: req.method||'GET', url: req.url||'', headers: JSON.stringify(req.headers||{},null,2), body: req.body||'' });
    setRepResp(null);
    setTab('repeater');
  };

  const sendRepeater = async () => {
    try {
      let headers = {};
      try { headers = JSON.parse(repeaterReq.headers); } catch {}
      const r = await api.post('/mobile/repeater/send', { device_id:deviceId, ...repeaterReq, headers });
      setRepResp(r.data?.response);
      setRepHistory(h => [r.data, ...h].slice(0,50));
    } catch (e) { setRepResp({ status_code:0, body:`Error: ${e.message}` }); }
  };

  // ── Filtered traffic ────────────────────────────────────────────────────────
  const filtered = traffic.filter(e => {
    if (sourceFilter !== 'all' && e.source !== sourceFilter) return false;
    if (urlFilter && !(e.request?.url||'').toLowerCase().includes(urlFilter.toLowerCase())) return false;
    return true;
  });

  // ── Layer status display ────────────────────────────────────────────────────
  const layers = sessionStatus?.layers || {};

  return (
    <div style={s.root}>
      {/* Toolbar */}
      <div style={s.toolbar}>
        {!captureRunning ? (
          <button style={s.btn('#00ff88')} onClick={startCapture} disabled={!deviceId}>
            ▶ Start Capture
          </button>
        ) : (
          <button style={s.btn('#ff4444')} onClick={stopCapture}>
            ⏹ Stop
          </button>
        )}

        {captureRunning && (
          <button style={s.btn(interceptOn ? '#ff4444' : '#ffaa00')} onClick={toggleIntercept}>
            {interceptOn ? '🔴 Intercept ON' : '⚪ Intercept OFF'}
          </button>
        )}

        {/* Source filter pills */}
        {['all','mitm','frida_ssl','ebpf','tcpdump','vpn'].map(src => (
          <span key={src} style={s.pill(sourceFilter===src, SOURCE_COLORS[src]||'#aaa')}
                onClick={() => setSrcFilter(src)}>
            {src==='all' ? 'ALL' : SOURCE_LABELS[src]}
          </span>
        ))}

        <input style={{ ...s.input, width:160, marginLeft:4 }}
               placeholder="Filter URL…"
               value={urlFilter} onChange={e => setUrlFilter(e.target.value)} />

        <button style={s.btn('#ffaa00')}
                onClick={() => window.open(`${import.meta.env.VITE_BACKEND_URL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:47291'}/api/mobile/agent/traffic/${deviceId}/export/har`,'_blank')}>
          📤 HAR
        </button>
        <button style={s.btn('#555')} onClick={async () => {
          setTraffic([]);
          setSelected(null);
          await api.delete(`/mobile/agent/traffic/${deviceId}`).catch(() => {});
        }}>Clear</button>

        <span style={{ marginLeft:'auto', fontSize:10, color:'#444' }}>
          {filtered.length} / {traffic.length}
          {interceptOn && pending.length > 0 && (
            <span style={{ marginLeft:6, color:'#ff8800' }}>⏸ {pending.length} paused</span>
          )}
        </span>
      </div>

      {/* Layer status bar */}
      {captureRunning && (
        <div style={s.statusBar}>
          {Object.entries(layers).map(([name, layer]) => (
            <span key={name} style={s.layerPill(layer.running, !!layer.error)}>
              {LAYER_ICONS[name] || '●'} {SOURCE_LABELS[name] || name}
              {layer.running ? ' ✓' : layer.error ? ' ✗' : ' …'}
            </span>
          ))}
          {sessionStatus?.entry_count > 0 && (
            <span style={{ fontSize:10, color:'#444', marginLeft:'auto' }}>
              {sessionStatus.entry_count} total captured
            </span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display:'flex', borderBottom:'1px solid #1a1a1a', background:'#0d0d0d' }}>
        {['history','intercept','repeater'].map(t => (
          <button key={t} style={s.tab(activeTab===t)} onClick={() => setTab(t)}>
            {t==='history' ? '📋 History'
              : t==='intercept' ? `⏸ Intercept${pending.length>0?` (${pending.length})`:''}`
              : '🔁 Repeater'}
          </button>
        ))}
      </div>

      {/* ── History tab ──────────────────────────────────────────────────────── */}
      {activeTab === 'history' && (
        <div style={s.body}>
          <div style={s.left}>
            <div style={s.tableHead}>
              <span>#</span><span>Layer</span><span>Method</span><span>URL</span>
              <span>Status</span><span>Decrypt</span><span>ms</span>
            </div>
            {filtered.length === 0 && (
              <div style={{ padding:24, color:'#333', textAlign:'center' }}>
                {captureRunning ? 'Waiting for traffic…' : 'Click ▶ Start Capture to begin'}
              </div>
            )}
            {filtered.map((entry, idx) => {
              const req  = entry.request  || {};
              const resp = entry.response || {};
              const src  = entry.source   || 'unknown';
              const isSel = !!selected && (
                entry.id != null ? selected.id === entry.id : selected === entry
              );
              return (
                <div key={entry.id ?? idx} style={s.tableRow(isSel)}
                     onClick={() => setSelected(isSel ? null : entry)}>
                  <span style={{ color:'#333' }}>{filtered.length - idx}</span>
                  <span style={s.badge(SOURCE_COLORS[src]||'#555')}>{SOURCE_LABELS[src]||'?'}</span>
                  <span style={{ color:METHOD_COLORS[req.method]||'#aaa', fontWeight:700 }}>
                    {req.method||'?'}
                  </span>
                  <span style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', color:'#bbb' }}>
                    {(req.url||'').replace(/^https?:\/\//,'')}
                  </span>
                  <span style={{ color: resp.status_code>=400?'#ff4444': resp.status_code>=200?'#00ff88':'#888' }}>
                    {resp.status_code||'—'}
                  </span>
                  <span style={s.decBadge(entry.decrypted)}>{entry.decrypted?'🔓':'🔒'}</span>
                  <span style={{ color:'#444' }}>{entry.duration_ms||'—'}</span>
                </div>
              );
            })}
          </div>

          <div style={s.right}>
            {selected ? (
              <>
                {/* Meta row */}
                <div style={{ display:'flex', gap:6, marginBottom:8, flexWrap:'wrap', alignItems:'center' }}>
                  <span style={s.badge(SOURCE_COLORS[selected.source]||'#555')}>
                    {SOURCE_LABELS[selected.source]||selected.source||'?'}
                  </span>
                  <span style={s.decBadge(selected.decrypted)}>
                    {selected.decrypted ? '🔓 Decrypted' : '🔒 Encrypted'}
                  </span>
                  {selected.duration_ms > 0 &&
                    <span style={{ fontSize:10, color:'#555' }}>{selected.duration_ms} ms</span>}
                  {selected.timestamp &&
                    <span style={{ fontSize:10, color:'#444', marginLeft:'auto' }}>
                      {new Date(selected.timestamp * 1000).toLocaleTimeString()}
                    </span>}
                </div>

                {/* Action buttons */}
                <div style={{ display:'flex', gap:6, marginBottom:10, flexWrap:'wrap' }}>
                  <button style={s.btn('#00aaff')} onClick={() => sendToRepeater(selected)}>🔁 Repeater</button>
                  <button style={s.btn('#ff8800')} onClick={() => {
                    api.post('/mobile/attack/inject', { device_id:deviceId, url:selected.request?.url, method:selected.request?.method }).catch(()=>{});
                  }}>⚡ Attack</button>
                </div>

                {/* Request */}
                <div style={s.sectionHdr}>Request</div>
                <div style={{ marginBottom:6, wordBreak:'break-all' }}>
                  <span style={{ color:METHOD_COLORS[selected.request?.method]||'#aaa', fontWeight:700, marginRight:8 }}>
                    {selected.request?.method || '—'}
                  </span>
                  <span style={{ color:'#ddd' }}>{selected.request?.url || '—'}</span>
                </div>

                <div style={s.sectionHdr}>Request Headers</div>
                <pre style={{ ...s.pre, maxHeight:140 }}>
                  {Object.keys(selected.request?.headers||{}).length > 0
                    ? JSON.stringify(selected.request.headers, null, 2)
                    : '(none)'}
                </pre>

                <div style={s.sectionHdr}>Request Body</div>
                <pre style={{ ...s.pre, maxHeight:160 }}>
                  {selected.request?.body || '(empty)'}
                </pre>

                {/* Response */}
                <div style={{ ...s.sectionHdr, marginTop:14 }}>
                  Response
                  {selected.response?.status_code > 0 &&
                    <span style={{ color: selected.response.status_code>=400?'#ff4444':'#00ff88', marginLeft:6, fontWeight:700 }}>
                      {selected.response.status_code}
                    </span>}
                </div>

                <div style={s.sectionHdr}>Response Headers</div>
                <pre style={{ ...s.pre, maxHeight:120 }}>
                  {Object.keys(selected.response?.headers||{}).length > 0
                    ? JSON.stringify(selected.response.headers, null, 2)
                    : '(none)'}
                </pre>

                <div style={s.sectionHdr}>Response Body</div>
                <pre style={{ ...s.pre, maxHeight:200 }}>
                  {selected.response?.body
                    ? selected.response.body.substring(0, 8192)
                    : '(empty)'}
                </pre>
              </>
            ) : (
              <div style={{ color:'#333', marginTop:60, textAlign:'center', fontSize:13 }}>
                ← Select a request to inspect
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Intercept tab ────────────────────────────────────────────────────── */}
      {activeTab === 'intercept' && (
        <div style={{ padding:12, overflowY:'auto', flex:1 }}>
          {!interceptOn && (
            <div style={{ color:'#555', marginBottom:10, padding:'8px 12px', background:'#111', borderRadius:4 }}>
              Toggle <strong style={{ color:'#ffaa00' }}>Intercept</strong> above to pause requests mid-flight.
              Layer-aware: mitmproxy handles normal apps, Frida handles cert-pinned apps.
            </div>
          )}
          {pending.length === 0 ? (
            <div style={{ color:'#333', textAlign:'center', marginTop:60 }}>
              {interceptOn ? '⏳ Waiting for requests…' : 'Intercept is OFF'}
            </div>
          ) : pending.map(bp => {
            const bpId = bp.breakpoint_id || bp.flow_id;
            return (
              <div key={bpId} style={s.interceptCard}>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:6 }}>
                  <span style={s.badge(bp.source==='mitm'?'#00ff88':'#00aaff')}>
                    {bp.source==='mitm' ? 'MITM' : 'FRIDA'}
                  </span>
                  <span style={{ color:'#ff8800', fontWeight:700 }}>{bp.method}</span>
                  <span style={{ color:'#ddd', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {bp.url}
                  </span>
                </div>
                <div style={{ fontSize:10, color:'#444', marginBottom:8 }}>
                  ID: {bpId} · {bp.raw_size||0} bytes
                </div>
                {editBp === bpId ? (
                  <>
                    <div style={s.sectionHdr}>Edit Request Body / Headers</div>
                    <textarea style={s.textarea} value={editedBody}
                              onChange={e => setEditedBody(e.target.value)} />
                    <div style={{ marginTop:8 }}>
                      <button style={s.btn('#00ff88')} onClick={() => releaseBp(bp, true)}>✅ Forward Modified</button>
                      <button style={s.btn('#ffaa00')} onClick={() => releaseBp(bp, false)}>▶ Forward Original</button>
                      <button style={s.btn('#ff4444')} onClick={() => setEditBp(null)}>Cancel</button>
                    </div>
                  </>
                ) : (
                  <div style={{ display:'flex', gap:6 }}>
                    <button style={s.btn('#00aaff')} onClick={() => { setEditBp(bpId); setEditedBody(bp.raw_data||bp.body||''); }}>
                      ✏️ Edit
                    </button>
                    <button style={s.btn('#00ff88')} onClick={() => releaseBp(bp, false)}>▶ Forward</button>
                    <button style={s.btn('#ffaa00')} onClick={() => sendToRepeater({ request: bp })}>🔁</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Repeater tab ─────────────────────────────────────────────────────── */}
      {activeTab === 'repeater' && (
        <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
          <div style={{ flex:1, padding:12, overflowY:'auto', borderRight:'1px solid #1a1a1a' }}>
            <div style={{ display:'flex', gap:6, marginBottom:8, alignItems:'center' }}>
              <select style={{ ...s.input, width:90 }} value={repeaterReq.method}
                      onChange={e => setRep(r=>({...r,method:e.target.value}))}>
                {['GET','POST','PUT','DELETE','PATCH','HEAD'].map(m=><option key={m}>{m}</option>)}
              </select>
              <input style={{ ...s.input, flex:1 }} placeholder="https://target.com/api/…"
                     value={repeaterReq.url} onChange={e => setRep(r=>({...r,url:e.target.value}))} />
              <button style={s.btn('#00ff88')} onClick={sendRepeater}>Send</button>
            </div>
            <div style={s.sectionHdr}>Headers (JSON)</div>
            <textarea style={s.textarea} value={repeaterReq.headers}
                      onChange={e=>setRep(r=>({...r,headers:e.target.value}))} />
            <div style={s.sectionHdr}>Body</div>
            <textarea style={s.textarea} value={repeaterReq.body}
                      onChange={e=>setRep(r=>({...r,body:e.target.value}))} />

            {repHistory.length > 0 && (
              <>
                <div style={{ ...s.sectionHdr, marginTop:16 }}>History</div>
                {repHistory.slice(0,10).map((h,i) => (
                  <div key={i} style={{ display:'flex', gap:8, padding:'4px 0', borderBottom:'1px solid #111', cursor:'pointer' }}
                       onClick={() => setRepResp(h.response)}>
                    <span style={{ color:METHOD_COLORS[h.request?.method]||'#aaa' }}>{h.request?.method}</span>
                    <span style={{ flex:1, color:'#555', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {(h.request?.url||'').replace(/^https?:\/\//,'')}
                    </span>
                    <span style={{ color:h.response?.status_code>=400?'#ff4444':'#00ff88' }}>
                      {h.response?.status_code}
                    </span>
                  </div>
                ))}
              </>
            )}
          </div>

          <div style={{ flex:1, padding:12, overflowY:'auto' }}>
            <div style={s.sectionHdr}>
              Response {repeaterResp?.status_code ? `· ${repeaterResp.status_code}` : ''}
              {repeaterResp?.timing_ms ? ` · ${repeaterResp.timing_ms}ms` : ''}
            </div>
            {repeaterResp ? (
              <pre style={{ ...s.pre, maxHeight:'none' }}>
                {(repeaterResp.body||'(empty)').substring(0,8192)}
              </pre>
            ) : (
              <div style={{ color:'#333', marginTop:60, textAlign:'center' }}>
                Response will appear here after sending
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
