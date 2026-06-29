import React, { useState, useEffect } from 'react'
import api from '../utils/api'

const SEVERITY_COLOR = {
  critical: 'bg-red-900 text-red-200 border-red-700',
  high:     'bg-orange-900 text-orange-200 border-orange-700',
  medium:   'bg-yellow-900 text-yellow-200 border-yellow-700',
  low:      'bg-blue-900 text-blue-200 border-blue-700',
  info:     'bg-gray-700 text-gray-300 border-gray-600',
}

const CATEGORY_ICON = {
  injection:    '💉',
  secret:       '🔑',
  oidc:         '🔐',
  supply_chain: '⛓️',
  permission:   '🛡️',
  runner:       '🏃',
}

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)
  const sev = (finding.severity || 'info').toLowerCase()
  return (
    <div className={`rounded-lg border p-4 mb-3 ${SEVERITY_COLOR[sev] || SEVERITY_COLOR.info}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-lg">{CATEGORY_ICON[finding.category] || '⚠️'}</span>
            <span className="font-semibold">{finding.title}</span>
            <span className={`text-xs px-2 py-0.5 rounded uppercase font-bold ${SEVERITY_COLOR[sev]}`}>
              {sev}
            </span>
          </div>
          <div className="text-sm opacity-80">{finding.description}</div>
          {finding.file_path && (
            <div className="text-xs opacity-60 mt-1 font-mono">{finding.file_path}
              {finding.line_number > 0 && `:${finding.line_number}`}
            </div>
          )}
        </div>
        <button onClick={() => setExpanded(!expanded)} className="text-xs opacity-60 hover:opacity-100 ml-4 mt-1">
          {expanded ? 'Less' : 'More'}
        </button>
      </div>
      {expanded && (
        <div className="mt-3 space-y-2 text-sm">
          {finding.evidence && (
            <div>
              <div className="text-xs uppercase opacity-60 mb-1">Evidence</div>
              <pre className="bg-black/30 rounded p-2 text-xs overflow-x-auto whitespace-pre-wrap">{finding.evidence}</pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <div className="text-xs uppercase opacity-60 mb-1">Remediation</div>
              <div className="opacity-80">{finding.remediation}</div>
            </div>
          )}
          {finding.cvss_score > 0 && <div className="text-xs">CVSS: <strong>{finding.cvss_score}</strong></div>}
          {finding.cwe && <div className="text-xs">CWE: <strong>{finding.cwe}</strong></div>}
        </div>
      )}
    </div>
  )
}

export default function CICDCenter() {
  const [repo, setRepo]         = useState('')
  const [scans, setScans]       = useState([])
  const [activeScan, setActiveScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [filterSev, setFilterSev] = useState('all')

  useEffect(() => {
    api.get('/cicd/scans').then(r => setScans(r.data.scans || [])).catch(() => {})
  }, [])

  useEffect(() => {
    if (!activeScan) return
    if (activeScan.status === 'running') {
      const id = setInterval(async () => {
        try {
          const r = await api.get(`/cicd/scans/${activeScan.scan_id}`)
          setActiveScan(r.data)
          if (r.data.status !== 'running') {
            setFindings(r.data.findings || [])
            clearInterval(id)
          }
        } catch { clearInterval(id) }
      }, 2000)
      return () => clearInterval(id)
    } else {
      setFindings(activeScan.findings || [])
    }
  }, [activeScan?.scan_id, activeScan?.status])

  const runScan = async () => {
    if (!repo.trim()) return
    setLoading(true)
    setError(null)
    setFindings([])
    try {
      const r = await api.post('/cicd/scan', { repo: repo.trim() })
      setActiveScan(r.data)
      setScans(prev => [r.data, ...prev])
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const loadScan = async (scan) => {
    setActiveScan(scan)
    const r = await api.get(`/cicd/scans/${scan.scan_id}`)
    setActiveScan(r.data)
    setFindings(r.data.findings || [])
  }

  const filtered = filterSev === 'all' ? findings
    : findings.filter(f => f.severity === filterSev)

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-6xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold">CI/CD Security Center</h1>
          <p className="text-gray-400 text-sm mt-1">
            Scan GitHub Actions, GitLab CI, and Jenkins pipelines for injection, secrets, supply chain risks
          </p>
        </div>

        {/* Scan Form */}
        <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700 mb-6">
          <div className="flex gap-3">
            <input
              value={repo}
              onChange={e => setRepo(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runScan()}
              placeholder="owner/repo or https://github.com/owner/repo"
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 outline-none"
            />
            <button
              onClick={runScan}
              disabled={loading || !repo.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded font-medium disabled:opacity-50"
            >
              {loading ? 'Scanning…' : 'Scan Pipeline'}
            </button>
          </div>
          {error && <div className="text-red-400 text-sm mt-2">{error}</div>}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Scan History */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 text-sm text-gray-400 uppercase tracking-wide">
                Scan History
              </div>
              {scans.length === 0 ? (
                <div className="p-4 text-gray-500 text-sm">No scans yet</div>
              ) : (
                scans.slice(0, 20).map(s => (
                  <button
                    key={s.scan_id}
                    onClick={() => loadScan(s)}
                    className={`w-full text-left px-4 py-3 border-b border-gray-700 hover:bg-gray-700/50 transition-colors ${
                      activeScan?.scan_id === s.scan_id ? 'bg-blue-900/30' : ''
                    }`}
                  >
                    <div className="text-sm text-white font-mono truncate">{s.repo}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`w-2 h-2 rounded-full ${
                        s.status === 'completed' ? 'bg-green-400' :
                        s.status === 'running'   ? 'bg-yellow-400 animate-pulse' :
                        s.status === 'failed'    ? 'bg-red-400' : 'bg-gray-500'
                      }`} />
                      <span className="text-xs text-gray-400">{s.status}</span>
                      {s.finding_count > 0 && (
                        <span className="text-xs text-red-400 ml-auto">{s.finding_count} findings</span>
                      )}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Results */}
          <div className="lg:col-span-3">
            {activeScan ? (
              <>
                {/* Status bar */}
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700 mb-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-mono text-white">{activeScan.repo}</span>
                      <span className={`ml-3 text-xs px-2 py-0.5 rounded ${
                        activeScan.status === 'completed' ? 'bg-green-900 text-green-300' :
                        activeScan.status === 'running'   ? 'bg-yellow-900 text-yellow-300' :
                        activeScan.status === 'failed'    ? 'bg-red-900 text-red-300' :
                        'bg-gray-700 text-gray-400'
                      }`}>{activeScan.status}</span>
                    </div>
                    {activeScan.status === 'running' && (
                      <div className="text-yellow-400 text-sm animate-pulse">Scanning…</div>
                    )}
                  </div>
                  {/* Severity summary */}
                  {findings.length > 0 && (
                    <div className="flex gap-3 mt-3">
                      {['critical','high','medium','low','info'].map(sev => counts[sev] ? (
                        <button
                          key={sev}
                          onClick={() => setFilterSev(filterSev === sev ? 'all' : sev)}
                          className={`text-xs px-2 py-1 rounded border ${SEVERITY_COLOR[sev]} ${
                            filterSev === sev ? 'ring-2 ring-white/30' : ''
                          }`}
                        >
                          {counts[sev]} {sev}
                        </button>
                      ) : null)}
                      {filterSev !== 'all' && (
                        <button onClick={() => setFilterSev('all')} className="text-xs text-gray-400 hover:text-white">
                          clear filter
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {/* Findings */}
                {activeScan.status === 'running' ? (
                  <div className="text-gray-400 text-center py-12">Scanning pipeline… results will appear here</div>
                ) : filtered.length === 0 ? (
                  <div className="text-gray-500 text-center py-12">
                    {findings.length === 0
                      ? '✅ No pipeline vulnerabilities found'
                      : `No ${filterSev} severity findings`}
                  </div>
                ) : (
                  <div>{filtered.map((f, i) => <FindingCard key={i} finding={f} />)}</div>
                )}
              </>
            ) : (
              <div className="text-gray-500 text-center py-24">
                Enter a GitHub repository to scan for CI/CD vulnerabilities
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
