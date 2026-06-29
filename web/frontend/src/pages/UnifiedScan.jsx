import { useState, useEffect } from 'react'
import { Search, Shield, Code, Globe, Zap, AlertTriangle, CheckCircle, Clock, Target, GitBranch, Users, Database, FileCode, Key, TrendingUp, Activity, Download } from 'lucide-react'
import { endpoints } from '../utils/api'
import clsx from 'clsx'

export default function UnifiedScan() {
  const [target, setTarget] = useState('')
  const [targetError, setTargetError] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [githubToken, setGithubToken] = useState('')
  const [maxRepos, setMaxRepos] = useState(100)
  const [maxDorks, setMaxDorks] = useState(30)
  const [loadedTokensCount, setLoadedTokensCount] = useState(0)
  const [rateLimits, setRateLimits] = useState(null)

  useEffect(() => {
    loadScans()
    loadGithubTokens()
    loadRateLimits()
    const interval = setInterval(() => {
      loadScans()
      loadRateLimits()
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadRateLimits = async () => {
    try {
      const r = await endpoints.githubRateLimit()
      setRateLimits(r.data)
    } catch (e) {
      console.error('Failed to load rate limits', e)
    }
  }

  const loadGithubTokens = async () => {
    try {
      const r = await endpoints.getGithubTokens()
      const tokens = r.data.tokens || []
      if (tokens.length > 0) {
        setLoadedTokensCount(tokens.length)
        // Use first token as display token (masked)
        setGithubToken(tokens[0])
      }
    } catch (e) {
      console.error('Failed to load GitHub tokens', e)
    }
  }

  const loadScans = async () => {
    try {
      const r = await endpoints.unifiedScanList()
      setScans(r.data.scans.sort((a, b) => b.started_at - a.started_at))
    } catch (e) {
      console.error('Failed to load scans', e)
    }
  }

  const handleScan = async () => {
    if (!target.trim()) { setTargetError('Target domain or URL is required'); return }
    setTargetError('')
    setScanning(true)
    try {
      const payload = { target: target.trim() }
      // Only send token override if user manually entered one
      if (githubToken.trim() && loadedTokensCount === 0) {
        payload.github_token = githubToken.trim()
      }
      // Backend will use configured tokens from .env automatically
      payload.max_repos = maxRepos
      payload.max_dorks = maxDorks
      await endpoints.unifiedScanStart(payload)
      setTarget('')
      loadScans()
    } catch (e) {
      console.error('Failed to start scan', e)
    } finally {
      setScanning(false)
    }
  }

  const handleViewScan = async (unifiedId) => {
    try {
      const r = await endpoints.unifiedScanGet(unifiedId)
      console.log('Loaded scan:', r.data)

      // Validate data structure
      if (!r.data || !r.data.scans) {
        console.error('Invalid scan data:', r.data)
        return
      }

      setSelectedScan(r.data)
    } catch (e) {
      console.error('Failed to load scan', e)
      alert('Failed to load scan: ' + (e.response?.data?.detail || e.message))
    }
  }

  const relativeTime = (timestamp) => {
    const seconds = Math.floor((Date.now() - timestamp) / 1000)
    if (seconds < 60) return `${seconds}s ago`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
    return `${Math.floor(seconds / 86400)}d ago`
  }

  const getSeverityColor = (severity) => {
    if (severity === 'critical') return 'text-red-500'
    if (severity === 'high') return 'text-orange-500'
    if (severity === 'medium') return 'text-yellow-500'
    return 'text-slate-400'
  }

  return (
    <div className="p-6 space-y-6">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-purple-900/50 to-blue-900/50 rounded-lg p-8 border border-purple-500/30">
        <div className="flex items-center gap-4 mb-4">
          <Zap className="w-12 h-12 text-purple-400" />
          <div>
            <h1 className="text-3xl font-bold">Unified GitHub Intelligence</h1>
            <p className="text-slate-400 mt-1">Complete reconnaissance: domain mapping + secrets + code search</p>
          </div>
        </div>

        {/* Main Scan Input */}
        <div className="space-y-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="facebook, facebook.com, google, microsoft..."
              className="flex-1 bg-slate-800 rounded-lg px-4 py-3 text-lg focus:ring-2 focus:ring-purple-500 outline-none"
            />
            <button
              onClick={handleScan}
              disabled={scanning}
              className="bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 rounded-lg px-8 py-3 font-semibold flex items-center gap-2"
            >
              {scanning ? <Clock className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
              {scanning ? 'Scanning...' : 'Scan'}
            </button>
          </div>
          {targetError && (
            <p className="text-xs text-red-400 mt-1 flex items-center gap-1">
              <AlertTriangle size={12} /> {targetError}
            </p>
          )}

          {/* Advanced Options */}
          <details className="bg-slate-800/50 rounded-lg p-4">
            <summary className="cursor-pointer text-sm text-slate-400 hover:text-white">Advanced Options</summary>
            <div className="mt-4 space-y-3">
              {loadedTokensCount > 0 && (
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-green-400">
                    {loadedTokensCount} GitHub token{loadedTokensCount > 1 ? 's' : ''} loaded from Settings
                  </span>
                </div>
              )}
              {rateLimits && (
                <div className="bg-slate-700/50 rounded-lg p-3">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs text-slate-400">GitHub API Rate Limit</span>
                    <span className={clsx('text-xs font-mono', 
                      rateLimits.remaining < 100 ? 'text-red-400' : 'text-green-400'
                    )}>
                      {rateLimits.remaining} / {rateLimits.limit}
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div 
                      className={clsx('h-full transition-all duration-1000', 
                        rateLimits.remaining < 100 ? 'bg-red-500' : 'bg-green-500'
                      )}
                      style={{ width: `${(rateLimits.remaining / rateLimits.limit) * 100}%` }}
                    />
                  </div>
                </div>
              )}
              <div>
                <label className="block text-slate-400 text-sm mb-1">
                  GitHub Token Override (Optional)
                  {loadedTokensCount === 0 && <span className="text-yellow-400 ml-2">⚠ No tokens in Settings</span>}
                </label>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder={loadedTokensCount > 0 ? "Using configured tokens..." : "ghp_xxxxxxxxxxxx"}
                  className="w-full bg-slate-700 rounded px-3 py-2 font-mono text-sm"
                />
                {loadedTokensCount === 0 && (
                  <p className="text-xs text-slate-500 mt-1">
                    Configure tokens in <a href="/settings" className="text-purple-400 hover:underline">Settings</a> for automatic rotation
                  </p>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 text-sm mb-1">Max Repos: {maxRepos}</label>
                  <input
                    type="range"
                    min="50"
                    max="500"
                    step="50"
                    value={maxRepos}
                    onChange={(e) => setMaxRepos(parseInt(e.target.value))}
                    className="w-full"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 text-sm mb-1">Max Dorks: {maxDorks}</label>
                  <input
                    type="range"
                    min="10"
                    max="50"
                    step="10"
                    value={maxDorks}
                    onChange={(e) => setMaxDorks(parseInt(e.target.value))}
                    className="w-full"
                  />
                </div>
              </div>
            </div>
          </details>
        </div>
      </div>

      {/* Scan History */}
      <div className="grid grid-cols-1 gap-4">
        {scans.length === 0 ? (
          <div className="bg-slate-800 rounded-lg p-12 text-center">
            <Target className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400 text-lg">No scans yet. Start your first unified reconnaissance!</p>
          </div>
        ) : (
          scans.map(scan => (
            <div
              key={scan.unified_id}
              onClick={() => handleViewScan(scan.unified_id)}
              className="bg-slate-800 rounded-lg p-6 hover:bg-slate-750 cursor-pointer transition-all border border-slate-700 hover:border-purple-500/50"
            >
              {/* Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                    <Zap className="w-6 h-6 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="text-xl font-bold">{scan.target}</h3>
                    <p className="text-slate-400 text-sm">{relativeTime(scan.started_at * 1000)}</p>
                  </div>
                </div>
                <div className={clsx(
                  'px-3 py-1 rounded-full text-sm font-semibold flex items-center gap-2',
                  scan.status === 'running' ? 'bg-yellow-500/20 text-yellow-500' :
                  scan.status === 'completed' ? 'bg-green-500/20 text-green-500' :
                  'bg-red-500/20 text-red-500'
                )}>
                  {scan.status === 'running' && <Clock className="w-4 h-4 animate-spin" />}
                  {scan.status === 'completed' && <CheckCircle className="w-4 h-4" />}
                  {scan.status}
                </div>
              </div>

              {/* Progress Pills */}
              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className={clsx(
                  'bg-slate-700 rounded-lg p-3 flex items-center gap-2',
                  scan.scans.domain_mapping.status === 'completed' && 'ring-2 ring-green-500/50'
                )}>
                  <Globe className="w-4 h-4 text-blue-400" />
                  <span className="text-sm">Domain Mapping</span>
                </div>
                <div className={clsx(
                  'bg-slate-700 rounded-lg p-3 flex items-center gap-2',
                  scan.scans.secrets.status === 'completed' && 'ring-2 ring-green-500/50'
                )}>
                  <Shield className="w-4 h-4 text-red-400" />
                  <span className="text-sm">Secrets</span>
                </div>
                <div className={clsx(
                  'bg-slate-700 rounded-lg p-3 flex items-center gap-2',
                  scan.scans.code_search.status === 'completed' && 'ring-2 ring-green-500/50'
                )}>
                  <Code className="w-4 h-4 text-purple-400" />
                  <span className="text-sm">Code Search</span>
                </div>
              </div>

              {/* Summary Stats */}
              {scan.summary && Object.keys(scan.summary).length > 0 && (
                <div className="grid grid-cols-4 gap-3">
                  <div className="bg-slate-700/50 rounded p-2">
                    <div className="text-slate-400 text-xs">Repos</div>
                    <div className="text-lg font-bold">{scan.summary.total_repos}</div>
                  </div>
                  <div className="bg-slate-700/50 rounded p-2">
                    <div className="text-slate-400 text-xs">Domains</div>
                    <div className="text-lg font-bold text-blue-400">{scan.summary.total_domains}</div>
                  </div>
                  <div className="bg-slate-700/50 rounded p-2">
                    <div className="text-slate-400 text-xs">Secrets</div>
                    <div className="text-lg font-bold text-red-400">{scan.summary.secrets_found}</div>
                  </div>
                  <div className="bg-slate-700/50 rounded p-2">
                    <div className="text-slate-400 text-xs">Critical</div>
                    <div className="text-lg font-bold text-orange-400">{scan.summary.critical_findings}</div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Detail Modal */}
      {selectedScan && selectedScan.scans && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-6" onClick={() => setSelectedScan(null)}>
          <div className="bg-slate-900 rounded-lg max-w-7xl w-full max-h-[90vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
            {/* Modal Header */}
            <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 z-10">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center">
                    <Zap className="w-8 h-8 text-white" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold">{selectedScan.target}</h2>
                    <p className="text-slate-400">Unified Intelligence Report</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <a
                    href={`/api/github-recon/unified-scan/${selectedScan.unified_id}/export?format=csv`}
                    download
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded flex items-center gap-2 text-sm"
                  >
                    <Download className="w-4 h-4" />
                    Export CSV
                  </a>
                  <button onClick={() => setSelectedScan(null)} className="text-slate-400 hover:text-white text-2xl">✕</button>
                </div>
              </div>
            </div>

            {/* Summary Dashboard */}
            {selectedScan.summary && Object.keys(selectedScan.summary).length > 0 && (
              <div className="p-6 bg-gradient-to-r from-slate-800 to-slate-900">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <TrendingUp className="w-5 h-5 text-purple-400" />
                  Executive Summary
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-blue-500/30">
                    <GitBranch className="w-6 h-6 text-blue-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.total_repos}</div>
                    <div className="text-slate-400 text-sm">Repositories</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-purple-500/30">
                    <Globe className="w-6 h-6 text-purple-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.total_domains}</div>
                    <div className="text-slate-400 text-sm">Domains Found</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-green-500/30">
                    <Users className="w-6 h-6 text-green-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.total_contributors}</div>
                    <div className="text-slate-400 text-sm">Contributors</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-pink-500/30">
                    <Users className="w-6 h-6 text-pink-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.total_users || 0}</div>
                    <div className="text-slate-400 text-sm">Org Members</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-yellow-500/30">
                    <Database className="w-6 h-6 text-yellow-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.commits_scanned}</div>
                    <div className="text-slate-400 text-sm">Commits Scanned</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 border border-orange-500/30">
                    <Activity className="w-6 h-6 text-orange-400 mb-2" />
                    <div className="text-3xl font-bold">{selectedScan.summary.has_actions ? 'YES' : 'NO'}</div>
                    <div className="text-slate-400 text-sm">GitHub Actions</div>
                  </div>
                </div>

                <div className="grid grid-cols-4 gap-4 mt-4">
                  <div className="bg-red-500/10 rounded-lg p-4 border border-red-500/30">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <span className="text-sm text-red-400 font-semibold">Critical</span>
                    </div>
                    <div className="text-3xl font-bold text-red-400">{selectedScan.summary.critical_findings}</div>
                  </div>
                  <div className="bg-orange-500/10 rounded-lg p-4 border border-orange-500/30">
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="w-5 h-5 text-orange-400" />
                      <span className="text-sm text-orange-400 font-semibold">Secrets</span>
                    </div>
                    <div className="text-3xl font-bold text-orange-400">{selectedScan.summary.secrets_found}</div>
                  </div>
                  <div className="bg-purple-500/10 rounded-lg p-4 border border-purple-500/30">
                    <div className="flex items-center gap-2 mb-2">
                      <FileCode className="w-5 h-5 text-purple-400" />
                      <span className="text-sm text-purple-400 font-semibold">Code</span>
                    </div>
                    <div className="text-3xl font-bold text-purple-400">{selectedScan.summary.code_findings}</div>
                  </div>
                  <div className="bg-green-500/10 rounded-lg p-4 border border-green-500/30">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <span className="text-sm text-green-400 font-semibold">High Confidence</span>
                    </div>
                    <div className="text-3xl font-bold text-green-400">{selectedScan.summary.high_confidence_findings || 0}</div>
                  </div>
                </div>
              </div>
            )}

            {/* Detailed Sections */}
            <div className="p-6 space-y-6">
              {/* Secrets Findings */}
              {selectedScan.scans.secrets.findings && selectedScan.scans.secrets.findings.length > 0 && (
                <div className="bg-slate-800 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-red-400" />
                    Leaked Secrets ({selectedScan.scans.secrets.findings.length})
                  </h3>
                  <div className="space-y-3">
                    {selectedScan.scans.secrets.findings.slice(0, 10).map((f, idx) => (
                      <div key={idx} className="bg-slate-700 rounded-lg p-4 border-l-4 border-red-500">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <Key className={clsx('w-4 h-4', getSeverityColor(f.severity))} />
                            <span className="font-mono text-sm">{f.secret_type}</span>
                            <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold',
                              f.severity === 'critical' ? 'bg-red-500/20 text-red-500' : 'bg-yellow-500/20 text-yellow-500')}>
                              {f.severity}
                            </span>
                            <span className="text-xs text-slate-400">confidence: {(f.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                        <div className="text-sm text-slate-300">
                          <a href={f.commit_url || f.html_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                            {f.repo_full_name || f.repository}
                          </a>
                          <span className="text-slate-500"> / {f.file_path}</span>
                        </div>
                        <div className="bg-slate-900 rounded p-2 font-mono text-xs overflow-x-auto mt-2">
                          {f.matched_text || (f.matches && f.matches[0])}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Code Search Findings */}
              {selectedScan.scans.code_search.findings && selectedScan.scans.code_search.findings.length > 0 && (
                <div className="bg-slate-800 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Code className="w-5 h-5 text-purple-400" />
                    Code Search Results ({selectedScan.scans.code_search.findings.length})
                  </h3>
                  <div className="space-y-3">
                    {selectedScan.scans.code_search.findings.slice(0, 10).map((f, idx) => (
                      <div key={idx} className="bg-slate-700 rounded-lg p-4 border-l-4 border-purple-500">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <FileCode className={clsx('w-4 h-4', getSeverityColor(f.severity))} />
                            <span className="font-mono text-sm">{f.dork_used?.split('"')[1] || 'match'}</span>
                            <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold',
                              f.severity === 'critical' ? 'bg-red-500/20 text-red-500' : 'bg-yellow-500/20 text-yellow-500')}>
                              {f.severity}
                            </span>
                          </div>
                        </div>
                        <div className="text-sm text-slate-300">
                          <a href={f.html_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                            {f.repository}
                          </a>
                          <span className="text-slate-500"> / {f.file_path}</span>
                        </div>
                        {f.matches && f.matches.length > 0 && (
                          <div className="bg-slate-900 rounded p-2 font-mono text-xs overflow-x-auto mt-2 space-y-1">
                            {f.matches.slice(0, 2).map((m, i) => (
                              <div key={i} className="whitespace-pre-wrap break-all">{m}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Domain Mapping */}
              {selectedScan.scans.domain_mapping.data && (
                <div className="space-y-6">
                  <div className="bg-slate-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                      <Globe className="w-5 h-5 text-blue-400" />
                      Domain Intelligence
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h4 className="text-sm text-slate-400 mb-2">Domains Found</h4>
                        <div className="bg-slate-700 rounded p-3 max-h-40 overflow-y-auto">
                          {selectedScan.scans.domain_mapping.data.domains?.slice(0, 20).map((d, i) => (
                            <div key={i} className="text-sm text-blue-400 font-mono">{d}</div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <h4 className="text-sm text-slate-400 mb-2">Top Languages</h4>
                        <div className="bg-slate-700 rounded p-3 max-h-40 overflow-y-auto">
                          {selectedScan.scans.domain_mapping.data.languages &&
                            Object.entries(selectedScan.scans.domain_mapping.data.languages)
                              .slice(0, 10)
                              .map(([lang, bytes], i) => (
                                <div key={i} className="text-sm text-purple-400 flex justify-between">
                                  <span>{lang}</span>
                                  <span className="text-slate-500">{(bytes / 1024).toFixed(0)} KB</span>
                                </div>
                              ))
                          }
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Infrastructure Intel */}
                  <div className="bg-slate-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                      <Activity className="w-5 h-5 text-green-400" />
                      Infrastructure Assets
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <h4 className="text-sm text-slate-400 mb-2">S3 Buckets ({selectedScan.scans.domain_mapping.data.s3_buckets?.length || 0})</h4>
                        <div className="bg-slate-700 rounded p-3 max-h-40 overflow-y-auto space-y-1">
                          {selectedScan.scans.domain_mapping.data.s3_buckets?.map((s, i) => (
                            <div key={i} className="text-xs text-yellow-400 break-all">{s}</div>
                          ))}
                          {(!selectedScan.scans.domain_mapping.data.s3_buckets || selectedScan.scans.domain_mapping.data.s3_buckets.length === 0) && (
                            <div className="text-xs text-slate-500 italic">None found</div>
                          )}
                        </div>
                      </div>
                      <div>
                        <h4 className="text-sm text-slate-400 mb-2">Internal Domains ({selectedScan.scans.domain_mapping.data.internal_domains?.length || 0})</h4>
                        <div className="bg-slate-700 rounded p-3 max-h-40 overflow-y-auto space-y-1">
                          {selectedScan.scans.domain_mapping.data.internal_domains?.map((d, i) => (
                            <div key={i} className="text-xs text-blue-400 break-all">{d}</div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <h4 className="text-sm text-slate-400 mb-2">API Endpoints ({selectedScan.scans.domain_mapping.data.api_endpoints?.length || 0})</h4>
                        <div className="bg-slate-700 rounded p-3 max-h-40 overflow-y-auto space-y-1">
                          {selectedScan.scans.domain_mapping.data.api_endpoints?.slice(0, 50).map((a, i) => (
                            <div key={i} className="text-xs text-purple-400 break-all">{a}</div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Organization Members */}
              {selectedScan.scans.user_enum.users && selectedScan.scans.user_enum.users.length > 0 && (
                <div className="bg-slate-800 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Users className="w-5 h-5 text-pink-400" />
                    Organization Members ({selectedScan.scans.user_enum.users.length})
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
                    {selectedScan.scans.user_enum.users.slice(0, 50).map((u, idx) => (
                      <div key={idx} className="bg-slate-700 rounded-lg p-2 flex items-center gap-2 overflow-hidden">
                        <img src={u.avatar_url} alt="" className="w-8 h-8 rounded-full bg-slate-600" />
                        <div className="min-w-0">
                          <div className="text-sm font-medium truncate">{u.login}</div>
                          {u.type && <div className="text-[10px] text-slate-500 uppercase">{u.type}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
