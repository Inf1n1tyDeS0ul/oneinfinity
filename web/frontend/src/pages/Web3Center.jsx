import React, { useState, useEffect } from 'react'
import api from '../utils/api'

const SEVERITY_BADGE = {
  critical: 'bg-red-900 text-red-200',
  high:     'bg-orange-900 text-orange-200',
  medium:   'bg-yellow-900 text-yellow-200',
  low:      'bg-blue-900 text-blue-200',
  info:     'bg-gray-700 text-gray-300',
}

const SCAN_TYPE_INFO = {
  evm_token:             { icon: '🔷', label: 'EVM Token Analysis' },
  solana_token:          { icon: '◎',  label: 'Solana Token Analysis' },
  smart_contract_static: { icon: '📄', label: 'Smart Contract Static Analysis (Slither)' },
  unknown:               { icon: '🔍', label: 'Blockchain Security Scan' },
}

function FindingRow({ finding }) {
  const sev = (finding.severity || 'info').toLowerCase()
  return (
    <div className={`rounded-lg p-4 mb-3 border ${
      sev === 'critical' ? 'border-red-800 bg-red-900/20' :
      sev === 'high'     ? 'border-orange-800 bg-orange-900/20' :
      sev === 'medium'   ? 'border-yellow-800 bg-yellow-900/20' :
      'border-gray-700 bg-gray-800/30'
    }`}>
      <div className="flex items-start gap-3">
        <span className={`text-xs px-2 py-1 rounded font-bold flex-shrink-0 ${SEVERITY_BADGE[sev] || SEVERITY_BADGE.info}`}>
          {sev.toUpperCase()}
        </span>
        <div className="flex-1">
          <div className="font-medium text-white">{finding.title || finding.vuln_type}</div>
          {finding.description && (
            <div className="text-gray-400 text-sm mt-1">{finding.description}</div>
          )}
          <div className="text-xs text-gray-500 mt-1 font-mono">
            {finding.vuln_type} · {finding.tool}
            {finding.confidence && ` · confidence: ${Math.round(finding.confidence * 100)}%`}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Web3Center() {
  const [target, setTarget]     = useState('')
  const [rpcUrl, setRpcUrl]     = useState('')
  const [scans, setScans]       = useState([])
  const [activeScan, setActiveScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)

  useEffect(() => {
    api.get('/web3/scans').then(r => setScans(r.data.scans || [])).catch(() => {})
  }, [])

  useEffect(() => {
    if (!activeScan || activeScan.status !== 'running') return
    const id = setInterval(async () => {
      try {
        const r = await api.get(`/web3/scans/${activeScan.scan_id}`)
        setActiveScan(r.data)
        if (r.data.status !== 'running') {
          setFindings(r.data.findings || [])
          clearInterval(id)
        }
      } catch { clearInterval(id) }
    }, 2000)
    return () => clearInterval(id)
  }, [activeScan?.scan_id, activeScan?.status])

  const runScan = async () => {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setFindings([])
    try {
      const body = { target: target.trim() }
      if (rpcUrl.trim()) body.rpc_url = rpcUrl.trim()
      const r = await api.post('/web3/scan', body)
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
    const r = await api.get(`/web3/scans/${scan.scan_id}`)
    setActiveScan(r.data)
    setFindings(r.data.findings || [])
  }

  const scanTypeInfo = SCAN_TYPE_INFO[activeScan?.scan_type] || SCAN_TYPE_INFO.unknown
  const bySeverity = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-5xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold">Web3 Security Center</h1>
          <p className="text-gray-400 text-sm mt-1">
            Analyze EVM/Solana tokens and smart contracts for security vulnerabilities
          </p>
        </div>

        {/* Input */}
        <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700 mb-6">
          <div className="text-sm text-gray-400 mb-3">
            Supports: EVM address (0x…), Solana address, .sol file path, or contract directory
          </div>
          <div className="space-y-3">
            <div className="flex gap-3">
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runScan()}
                placeholder="0x... or Solana address or path/to/contract.sol"
                className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 outline-none font-mono text-sm"
              />
              <button
                onClick={runScan}
                disabled={loading || !target.trim()}
                className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded font-medium disabled:opacity-50 whitespace-nowrap"
              >
                {loading ? 'Scanning…' : 'Analyze'}
              </button>
            </div>
            <input
              value={rpcUrl}
              onChange={e => setRpcUrl(e.target.value)}
              placeholder="RPC URL (optional, for EVM on-chain data)"
              className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 outline-none text-sm"
            />
          </div>
          {error && <div className="text-red-400 text-sm mt-2">{error}</div>}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* History */}
          <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden h-fit">
            <div className="px-4 py-3 border-b border-gray-700 text-xs text-gray-400 uppercase tracking-wide">
              Scan History
            </div>
            {scans.length === 0 ? (
              <div className="p-4 text-gray-500 text-sm">No scans yet</div>
            ) : (
              scans.slice(0, 15).map(s => (
                <button
                  key={s.scan_id}
                  onClick={() => loadScan(s)}
                  className={`w-full text-left px-4 py-3 border-b border-gray-700/50 hover:bg-gray-700/50 ${
                    activeScan?.scan_id === s.scan_id ? 'bg-purple-900/20' : ''
                  }`}
                >
                  <div className="text-xs text-white font-mono truncate">{s.target}</div>
                  <div className="flex gap-2 mt-1 items-center">
                    <span className={`w-2 h-2 rounded-full ${
                      s.status === 'completed' ? 'bg-green-400' :
                      s.status === 'running'   ? 'bg-yellow-400 animate-pulse' :
                      'bg-red-400'
                    }`} />
                    <span className="text-xs text-gray-500">{s.status}</span>
                    {s.finding_count > 0 && (
                      <span className="text-xs text-red-400 ml-auto">{s.finding_count}</span>
                    )}
                  </div>
                </button>
              ))
            )}
          </div>

          {/* Results */}
          <div className="lg:col-span-3">
            {activeScan ? (
              <>
                <div className="bg-gray-800/50 rounded-lg p-4 border border-purple-900/50 mb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{scanTypeInfo.icon}</span>
                    <div>
                      <div className="font-medium text-white font-mono text-sm truncate">{activeScan.target}</div>
                      <div className="text-gray-400 text-xs">{scanTypeInfo.label}</div>
                    </div>
                    <span className={`ml-auto text-xs px-2 py-1 rounded ${
                      activeScan.status === 'completed' ? 'bg-green-900 text-green-300' :
                      activeScan.status === 'running'   ? 'bg-yellow-900 text-yellow-300 animate-pulse' :
                      'bg-red-900 text-red-300'
                    }`}>{activeScan.status}</span>
                  </div>
                  {/* Severity breakdown */}
                  {Object.keys(bySeverity).length > 0 && (
                    <div className="flex gap-3 mt-3 flex-wrap">
                      {['critical','high','medium','low','info'].filter(s => bySeverity[s]).map(sev => (
                        <span key={sev} className={`text-xs px-2 py-0.5 rounded ${SEVERITY_BADGE[sev]}`}>
                          {bySeverity[sev]} {sev}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {activeScan.status === 'running' ? (
                  <div className="text-gray-400 text-center py-16 animate-pulse">Analyzing…</div>
                ) : findings.length === 0 ? (
                  <div className="text-gray-500 text-center py-16">
                    ✅ No vulnerabilities detected
                  </div>
                ) : (
                  <div>{findings.map((f, i) => <FindingRow key={i} finding={f} />)}</div>
                )}
              </>
            ) : (
              <div className="text-gray-500 text-center py-24">
                Enter an address or contract path to begin analysis
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
