import React, { useState, useEffect } from 'react'
import api from '../utils/api'

function AccountRow({ account, index, onChange, onRemove }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 relative">
      <button
        onClick={onRemove}
        className="absolute top-3 right-3 text-gray-500 hover:text-red-400 text-xs"
      >✕</button>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs text-gray-400 block mb-1">Role</label>
          <select
            value={account.role}
            onChange={e => onChange(index, 'role', e.target.value)}
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white"
          >
            <option value="victim">victim</option>
            <option value="attacker">attacker</option>
            <option value="admin">admin</option>
            <option value="user">user</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Cookie</label>
          <input
            value={account.cookie}
            onChange={e => onChange(index, 'cookie', e.target.value)}
            placeholder="session=abc123"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white font-mono placeholder-gray-600"
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Auth Header</label>
          <input
            value={account.auth_header}
            onChange={e => onChange(index, 'auth_header', e.target.value)}
            placeholder="Bearer eyJ..."
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white font-mono placeholder-gray-600"
          />
        </div>
      </div>
    </div>
  )
}

function FindingCard({ finding }) {
  const sev = (finding.severity || 'medium').toLowerCase()
  return (
    <div className={`rounded-lg p-4 border mb-3 ${
      sev === 'critical' ? 'border-red-700 bg-red-900/20' :
      sev === 'high'     ? 'border-orange-700 bg-orange-900/20' :
      sev === 'medium'   ? 'border-yellow-700 bg-yellow-900/20' :
      'border-gray-700 bg-gray-800/30'
    }`}>
      <div className="flex items-start gap-3">
        <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase flex-shrink-0 ${
          sev === 'critical' ? 'bg-red-900 text-red-200' :
          sev === 'high'     ? 'bg-orange-900 text-orange-200' :
          sev === 'medium'   ? 'bg-yellow-900 text-yellow-200' :
          'bg-gray-700 text-gray-300'
        }`}>{sev}</span>
        <div>
          <div className="font-medium text-white">{finding.title}</div>
          {finding.url && <div className="text-xs text-gray-400 font-mono mt-1">{finding.url}</div>}
          {finding.evidence && (
            <pre className="text-xs text-gray-400 bg-black/30 rounded p-2 mt-2 overflow-x-auto whitespace-pre-wrap">
              {typeof finding.evidence === 'string' ? finding.evidence.slice(0, 400) : JSON.stringify(finding.evidence, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

export default function IDORCenter() {
  const [target, setTarget]         = useState('')
  const [accounts, setAccounts]     = useState([
    { role: 'victim',   cookie: '', auth_header: '' },
    { role: 'attacker', cookie: '', auth_header: '' },
  ])
  const [urls, setUrls]             = useState('')
  const [sessions, setSessions]     = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [findings, setFindings]     = useState([])
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  useEffect(() => {
    api.get('/idor/sessions').then(r => setSessions(r.data.sessions || [])).catch(() => {})
  }, [])

  useEffect(() => {
    if (!activeSession || activeSession.status !== 'running') return
    const id = setInterval(async () => {
      try {
        const r = await api.get(`/idor/sessions/${activeSession.session_id}`)
        setActiveSession(r.data)
        if (r.data.status !== 'running') {
          setFindings(r.data.findings || [])
          clearInterval(id)
        }
      } catch { clearInterval(id) }
    }, 2000)
    return () => clearInterval(id)
  }, [activeSession?.session_id, activeSession?.status])

  const addAccount = () => setAccounts(a => [...a, { role: 'user', cookie: '', auth_header: '' }])
  const removeAccount = (i) => setAccounts(a => a.filter((_, idx) => idx !== i))
  const updateAccount = (i, field, val) => setAccounts(a => a.map((acc, idx) => idx === i ? { ...acc, [field]: val } : acc))

  const createAndRun = async () => {
    if (!target.trim()) { setError('Target URL required'); return }
    if (accounts.length < 2) { setError('At least 2 accounts required for IDOR testing'); return }
    setLoading(true)
    setError(null)
    setFindings([])
    try {
      // Create session
      const createRes = await api.post('/idor/sessions', { target: target.trim(), accounts })
      const sessionId = createRes.data.session_id
      // Run test
      const urlList = urls.trim().split('\n').filter(u => u.trim())
      await api.post(`/idor/sessions/${sessionId}/test`, { urls: urlList })
      const sess = { ...createRes.data, status: 'running' }
      setActiveSession(sess)
      setSessions(prev => [sess, ...prev])
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const loadSession = async (sess) => {
    setActiveSession(sess)
    const r = await api.get(`/idor/sessions/${sess.session_id}`)
    setActiveSession(r.data)
    setFindings(r.data.findings || [])
  }

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-6xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold">Multi-Account IDOR Center</h1>
          <p className="text-gray-400 text-sm mt-1">
            Cross-account access testing with automated authorization differential analysis
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration */}
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700">
              <h2 className="font-semibold mb-3">Target</h2>
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="https://api.example.com"
                className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              />
            </div>

            <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700">
              <div className="flex items-center justify-between mb-3">
                <h2 className="font-semibold">Accounts ({accounts.length})</h2>
                <button
                  onClick={addAccount}
                  className="text-xs bg-blue-700 hover:bg-blue-600 text-white px-3 py-1 rounded"
                >+ Add Account</button>
              </div>
              <div className="space-y-3">
                {accounts.map((acc, i) => (
                  <AccountRow
                    key={i} account={acc} index={i}
                    onChange={updateAccount}
                    onRemove={() => removeAccount(i)}
                  />
                ))}
              </div>
            </div>

            <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700">
              <h2 className="font-semibold mb-3">URLs to Test (optional)</h2>
              <textarea
                value={urls}
                onChange={e => setUrls(e.target.value)}
                placeholder="One URL per line&#10;https://api.example.com/users/123&#10;https://api.example.com/orders/456"
                rows={4}
                className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500 text-sm font-mono"
              />
              <div className="text-xs text-gray-500 mt-1">
                Leave empty to use URLs from captured traffic
              </div>
            </div>

            {error && <div className="bg-red-900/30 border border-red-700 rounded p-3 text-red-300 text-sm">{error}</div>}

            <button
              onClick={createAndRun}
              disabled={loading}
              className="w-full bg-red-700 hover:bg-red-600 text-white py-3 rounded font-semibold disabled:opacity-50"
            >
              {loading ? 'Starting IDOR Test…' : '🔍 Run IDOR Test'}
            </button>
          </div>

          {/* Sessions + Results */}
          <div className="space-y-4">
            <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 text-xs text-gray-400 uppercase tracking-wide">
                Sessions
              </div>
              {sessions.length === 0 ? (
                <div className="p-4 text-gray-500 text-sm">No sessions yet</div>
              ) : (
                sessions.slice(0, 10).map(s => (
                  <button
                    key={s.session_id}
                    onClick={() => loadSession(s)}
                    className={`w-full text-left px-4 py-3 border-b border-gray-700/50 hover:bg-gray-700/50 ${
                      activeSession?.session_id === s.session_id ? 'bg-red-900/20' : ''
                    }`}
                  >
                    <div className="text-xs text-white truncate">{s.target}</div>
                    <div className="flex gap-2 mt-1">
                      <span className={`w-2 h-2 rounded-full self-center ${
                        s.status === 'completed' ? 'bg-green-400' :
                        s.status === 'running'   ? 'bg-yellow-400 animate-pulse' :
                        s.status === 'failed'    ? 'bg-red-400' : 'bg-gray-500'
                      }`} />
                      <span className="text-xs text-gray-400">{s.status}</span>
                    </div>
                  </button>
                ))
              )}
            </div>

            {/* Active session results */}
            {activeSession && (
              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  Results
                  {activeSession.status === 'running' && (
                    <span className="text-xs text-yellow-400 animate-pulse">Running…</span>
                  )}
                </h3>
                {activeSession.status === 'running' ? (
                  <div className="text-gray-500 text-sm text-center py-8 animate-pulse">
                    Testing cross-account access…
                  </div>
                ) : findings.length === 0 ? (
                  <div className="text-gray-500 text-sm text-center py-6">
                    {activeSession.status === 'failed'
                      ? `Error: ${activeSession.error}`
                      : 'No IDOR vulnerabilities found ✅'}
                  </div>
                ) : (
                  <div className="max-h-96 overflow-y-auto">
                    {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
