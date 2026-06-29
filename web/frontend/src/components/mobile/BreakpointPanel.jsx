import React, { useState, useEffect, useRef } from 'react';
import api from '../../utils/api';

const s = {
  panel:   { background: '#0a0a0a', color: '#ddd', fontFamily: 'monospace', padding: 16, borderRadius: 8 },
  header:  { fontSize: 15, fontWeight: 700, color: '#ff8800', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 },
  section: { background: '#111', border: '1px solid #1a1a2e', borderRadius: 4, padding: 12, marginBottom: 10 },
  label:   { fontSize: 10, color: '#555', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4, display: 'block' },
  input:   { width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 12, borderRadius: 4, boxSizing: 'border-box', fontFamily: 'monospace' },
  select:  { background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 12, borderRadius: 4, fontFamily: 'monospace' },
  textarea:{ width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 11, borderRadius: 4, resize: 'vertical', minHeight: 120, fontFamily: 'monospace', boxSizing: 'border-box' },
  btn:     { padding: '6px 14px', border: '1px solid #aa5500', background: '#1a0d00', borderRadius: 4, color: '#ff8800', cursor: 'pointer', fontSize: 12, marginRight: 6 },
  btnRel:  { padding: '6px 14px', border: '1px solid #00aa55', background: '#001a0d', borderRadius: 4, color: '#00ff88', cursor: 'pointer', fontSize: 12, marginRight: 6 },
  btnDel:  { padding: '4px 10px', border: '1px solid #550000', background: '#1a0000', borderRadius: 4, color: '#ff4444', cursor: 'pointer', fontSize: 11 },
  hitCard: { background: '#0f0f0f', border: '2px solid #ff8800', borderRadius: 6, padding: 12, marginBottom: 10 },
  hitUrl:  { fontSize: 12, color: '#ff8800', fontWeight: 700, marginBottom: 4, wordBreak: 'break-all' },
  method:  { fontSize: 10, padding: '2px 6px', borderRadius: 3, background: '#1a0a00', color: '#ff8800', marginRight: 6 },
};

export default function BreakpointPanel({ deviceId }) {
  const [rules, setRules] = useState([]);
  const [pending, setPending] = useState([]);
  const [editingBp, setEditingBp] = useState(null);
  const [editedBytes, setEditedBytes] = useState('');
  const [form, setForm] = useState({ url_pattern: '', direction: 'request' });
  const [error, setError] = useState('');
  const pollRef = useRef(null);

  // Poll for pending breakpoints every 1s
  useEffect(() => {
    if (!deviceId) return;
    const poll = async () => {
      try {
        const r = await api.get(`/mobile/breakpoint/pending/${deviceId}`);
        setPending(r.data || []);
      } catch { }
    };
    poll();
    pollRef.current = setInterval(poll, 1000);
    return () => clearInterval(pollRef.current);
  }, [deviceId]);

  const addRule = async () => {
    if (!form.url_pattern) { setError('URL pattern required'); return; }
    setError('');
    try {
      const res = await api.post('/mobile/breakpoint/rule', {
        device_id: deviceId,
        url_pattern: form.url_pattern,
        direction: form.direction,
        enabled: true,
      });
      setRules(prev => [...prev, { ...form, id: res.data.rule_id }]);
      setForm({ url_pattern: '', direction: 'request' });
    } catch (e) { setError(e.response?.data?.detail || 'Failed to add breakpoint'); }
  };

  const removeRule = async (ruleId) => {
    try {
      await api.delete(`/mobile/breakpoint/rule/${deviceId}/${ruleId}`);
      setRules(prev => prev.filter(r => r.id !== ruleId));
    } catch { }
  };

  const openEditor = (bp) => {
    setEditingBp(bp);
    // Show headers as editable text block
    const hdrs = bp.headers || {};
    const text = Object.entries(hdrs).map(([k, v]) => `${k}: ${v}`).join('\n');
    setEditedBytes(text);
  };

  const release = async (bpId, withEdit = false) => {
    try {
      await api.post(`/mobile/breakpoint/resume/${bpId}`, {
        modified_bytes: withEdit ? btoa(editedBytes) : '',
      });
      setPending(prev => prev.filter(b => b.breakpoint_id !== bpId));
      setEditingBp(null);
    } catch (e) { setError('Release failed: ' + (e.response?.data?.detail || e.message)); }
  };

  return (
    <div style={s.panel}>
      <div style={s.header}>
        <span>⏸</span>
        <span>Breakpoints</span>
        {pending.length > 0 && (
          <span style={{ fontSize: 10, background: '#ff8800', color: '#000', padding: '2px 6px', borderRadius: 10 }}>
            {pending.length} paused
          </span>
        )}
      </div>

      {/* Active rules */}
      <div style={s.section}>
        <label style={s.label}>Active Rules ({rules.length})</label>
        {rules.length === 0 ? (
          <div style={{ fontSize: 11, color: '#444' }}>No breakpoint rules set</div>
        ) : rules.map(r => (
          <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 11, color: '#aaa', flex: 1 }}>{r.url_pattern} [{r.direction}]</span>
            <button style={s.btnDel} onClick={() => removeRule(r.id)}>✕</button>
          </div>
        ))}

        <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={s.label}>URL Pattern</label>
            <input style={s.input} placeholder="*/api/auth*" value={form.url_pattern}
              onChange={e => setForm(p => ({ ...p, url_pattern: e.target.value }))} />
          </div>
          <div>
            <label style={s.label}>Direction</label>
            <select style={s.select} value={form.direction}
              onChange={e => setForm(p => ({ ...p, direction: e.target.value }))}>
              <option value="request">Request</option>
              <option value="response">Response</option>
              <option value="both">Both</option>
            </select>
          </div>
          <button style={s.btn} onClick={addRule} disabled={!deviceId}>+ Add</button>
        </div>
        {error && <div style={{ fontSize: 11, color: '#ff4444', marginTop: 6 }}>{error}</div>}
      </div>

      {/* Paused requests */}
      {pending.length > 0 && (
        <div style={s.section}>
          <label style={s.label}>⏸ Paused Requests ({pending.length})</label>
          {pending.map(bp => (
            <div key={bp.breakpoint_id} style={s.hitCard}>
              <div style={s.hitUrl}>
                <span style={s.method}>{bp.method}</span>
                {bp.url}
              </div>
              <div style={{ fontSize: 10, color: '#555', marginBottom: 8 }}>
                ID: {bp.breakpoint_id} · {bp.raw_size} bytes
              </div>
              {editingBp?.breakpoint_id === bp.breakpoint_id ? (
                <>
                  <label style={s.label}>Edit Headers (key: value per line)</label>
                  <textarea style={s.textarea} value={editedBytes}
                    onChange={e => setEditedBytes(e.target.value)} />
                  <div style={{ marginTop: 8 }}>
                    <button style={s.btnRel} onClick={() => release(bp.breakpoint_id, true)}>
                      ✅ Release Modified
                    </button>
                    <button style={s.btn} onClick={() => release(bp.breakpoint_id, false)}>
                      ▶ Release Original
                    </button>
                    <button style={s.btnDel} onClick={() => setEditingBp(null)}>Cancel</button>
                  </div>
                </>
              ) : (
                <div style={{ display: 'flex', gap: 6 }}>
                  <button style={s.btn} onClick={() => openEditor(bp)}>✏️ Edit & Release</button>
                  <button style={s.btnRel} onClick={() => release(bp.breakpoint_id, false)}>▶ Release</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
