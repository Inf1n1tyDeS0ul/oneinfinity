import React, { useState, useEffect } from 'react';
import api from '../../utils/api';

const MODES = [
  { value: 'redirect',         label: 'Redirect (Map Remote)' },
  { value: 'replace_request',  label: 'Replace Request Body' },
  { value: 'replace_response', label: 'Replace Response Body' },
  { value: 'modify_request',   label: 'Modify Request' },
  { value: 'modify_response',  label: 'Modify Response' },
];

const s = {
  panel:   { background: '#0a0a0a', color: '#ddd', fontFamily: 'monospace', padding: 16, borderRadius: 8 },
  header:  { fontSize: 15, fontWeight: 700, color: '#00ff88', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 },
  section: { background: '#111', border: '1px solid #1a1a2e', borderRadius: 4, padding: 12, marginBottom: 10 },
  label:   { fontSize: 10, color: '#555', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4, display: 'block' },
  input:   { width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 12, borderRadius: 4, boxSizing: 'border-box', fontFamily: 'monospace' },
  select:  { width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 12, borderRadius: 4, boxSizing: 'border-box', fontFamily: 'monospace' },
  textarea:{ width: '100%', background: '#060606', border: '1px solid #222', color: '#ddd', padding: '6px 8px', fontSize: 11, borderRadius: 4, resize: 'vertical', minHeight: 80, fontFamily: 'monospace', boxSizing: 'border-box' },
  btn:     { padding: '6px 14px', border: '1px solid #00aa55', background: '#001a0d', borderRadius: 4, color: '#00ff88', cursor: 'pointer', fontSize: 12, marginRight: 6 },
  btnDel:  { padding: '4px 10px', border: '1px solid #550000', background: '#1a0000', borderRadius: 4, color: '#ff4444', cursor: 'pointer', fontSize: 11 },
  badge:   { fontSize: 9, padding: '2px 6px', borderRadius: 3, marginRight: 4, textTransform: 'uppercase', letterSpacing: 1 },
  modeColors: { redirect: '#ff8800', replace_request: '#ff4444', replace_response: '#ff4444', modify_request: '#00aaff', modify_response: '#00aaff' },
  priority: ['redirect','replace_request','replace_response','modify_request','modify_response'],
};

export default function RewriteRulePanel({ deviceId }) {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({ url_pattern: '', mode: 'modify_request', destination: '', body: '', headers: '', params: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!deviceId) return;
    api.get(`/mobile/rewrite/rules/${deviceId}`).then(r => setRules(r.data)).catch(() => {});
  }, [deviceId]);

  const addRule = async () => {
    if (!form.url_pattern) { setError('URL pattern required'); return; }
    setLoading(true); setError('');
    try {
      const config = buildConfig(form);
      const res = await api.post('/mobile/rewrite/rule', {
        device_id: deviceId,
        url_pattern: form.url_pattern,
        mode: form.mode,
        config,
        enabled: true,
      });
      setRules(prev => [...prev, { ...form, config, id: res.data.rule_id, enabled: true }]);
      setForm({ url_pattern: '', mode: 'modify_request', destination: '', body: '', headers: '', params: '' });
    } catch (e) { setError(e.response?.data?.detail || 'Failed to add rule'); }
    setLoading(false);
  };

  const removeRule = async (ruleId) => {
    try {
      await api.delete(`/mobile/rewrite/rule/${deviceId}/${ruleId}`);
      setRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (e) { setError('Failed to remove rule'); }
  };

  const buildConfig = (f) => {
    const cfg = {};
    if (f.mode === 'redirect') { cfg.destination = f.destination; return cfg; }
    if (f.mode === 'replace_request' || f.mode === 'replace_response') { cfg.body = f.body; return cfg; }
    if (f.headers) { try { cfg.headers = JSON.parse(f.headers); } catch { cfg.headers = {}; } }
    if (f.params)  { try { cfg.params  = JSON.parse(f.params);  } catch { cfg.params  = {}; } }
    return cfg;
  };

  const priorityLabel = (mode) => {
    const idx = s.priority.indexOf(mode);
    return idx >= 0 ? `P${idx + 1}` : '';
  };

  return (
    <div style={s.panel}>
      <div style={s.header}>
        <span>⚙️</span>
        <span>Rewrite Rules</span>
        <span style={{ fontSize: 10, color: '#555', fontWeight: 400 }}>
          priority: redirect {'>'} replace {'>'} modify
        </span>
      </div>

      {/* Active rules */}
      {rules.length === 0 ? (
        <div style={{ fontSize: 11, color: '#444', marginBottom: 12 }}>No active rules</div>
      ) : (
        <div style={s.section}>
          {rules.map((rule, i) => (
            <div key={rule.id || i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, padding: '6px 8px', background: '#0a0a0a', borderRadius: 4 }}>
              <span style={{ ...s.badge, background: s.modeColors[rule.mode] + '22', color: s.modeColors[rule.mode] }}>
                {priorityLabel(rule.mode)} {rule.mode?.replace(/_/g, ' ')}
              </span>
              <span style={{ fontSize: 11, color: '#aaa', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {rule.url_pattern || '*'}
              </span>
              <button style={s.btnDel} onClick={() => removeRule(rule.id)}>✕</button>
            </div>
          ))}
        </div>
      )}

      {/* Add rule form */}
      <div style={s.section}>
        <label style={s.label}>Add Rule</label>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
          <div>
            <label style={{ ...s.label, marginTop: 4 }}>URL Pattern</label>
            <input style={s.input} placeholder="*/api/login*" value={form.url_pattern}
              onChange={e => setForm(p => ({ ...p, url_pattern: e.target.value }))} />
          </div>
          <div>
            <label style={{ ...s.label, marginTop: 4 }}>Mode</label>
            <select style={s.select} value={form.mode}
              onChange={e => setForm(p => ({ ...p, mode: e.target.value }))}>
              {MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </div>
        </div>

        {form.mode === 'redirect' && (
          <div style={{ marginBottom: 8 }}>
            <label style={s.label}>Destination URL (append /new/* to preserve path)</label>
            <input style={s.input} placeholder="https://attacker.com/new/*"
              value={form.destination} onChange={e => setForm(p => ({ ...p, destination: e.target.value }))} />
          </div>
        )}
        {(form.mode === 'replace_request' || form.mode === 'replace_response') && (
          <div style={{ marginBottom: 8 }}>
            <label style={s.label}>Replacement Body</label>
            <textarea style={s.textarea} placeholder='{"injected": true}'
              value={form.body} onChange={e => setForm(p => ({ ...p, body: e.target.value }))} />
          </div>
        )}
        {(form.mode === 'modify_request' || form.mode === 'modify_response') && (
          <>
            <div style={{ marginBottom: 8 }}>
              <label style={s.label}>Headers (JSON) — empty value removes header</label>
              <textarea style={{ ...s.textarea, minHeight: 50 }} placeholder='{"Authorization": "Bearer evil"}'
                value={form.headers} onChange={e => setForm(p => ({ ...p, headers: e.target.value }))} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label style={s.label}>Params (JSON)</label>
              <textarea style={{ ...s.textarea, minHeight: 50 }} placeholder='{"debug": "true"}'
                value={form.params} onChange={e => setForm(p => ({ ...p, params: e.target.value }))} />
            </div>
          </>
        )}

        {error && <div style={{ fontSize: 11, color: '#ff4444', marginBottom: 8 }}>{error}</div>}
        <button style={s.btn} onClick={addRule} disabled={loading || !deviceId}>
          {loading ? 'Adding…' : '+ Add Rule'}
        </button>
      </div>
    </div>
  );
}
