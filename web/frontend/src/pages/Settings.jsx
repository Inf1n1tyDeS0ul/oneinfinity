import { useState, useEffect } from 'react'
import { Save, Eye, EyeOff, Key, CheckCircle, AlertTriangle, Trash2, Plus, Github } from 'lucide-react'
import { endpoints } from '../utils/api'
import clsx from 'clsx'

export default function Settings() {
  const [githubTokens, setGithubTokens] = useState('')
  const [githubTokensVisible, setGithubTokensVisible] = useState(false)
  const [savedTokens, setSavedTokens] = useState([])
  const [saving, setSaving] = useState(false)
  const [notification, setNotification] = useState(null)

  const [apiKeys, setApiKeys] = useState({
    OPENAI_API_KEY: '',
    ANTHROPIC_API_KEY: '',
    SHODAN_API_KEY: '',
    VIRUSTOTAL_API_KEY: '',
    CENSYS_API_ID: '',
    CENSYS_API_SECRET: '',
    SECURITYTRAILS_API_KEY: '',
    URLSCAN_API_KEY: '',
    HUNTER_API_KEY: '',
  })
  const [apiKeysVisible, setApiKeysVisible] = useState({})
  const [hitlStats, setHitlStats] = useState(null)

  useEffect(() => {
    loadConfig()
    endpoints.hitlStats().then(r => setHitlStats(r.data?.stats || null)).catch(() => {})
  }, [])

  const loadConfig = async () => {
    try {
      // Load GitHub tokens
      const tokensResp = await endpoints.getGithubTokens()
      setSavedTokens(tokensResp.data.tokens || [])

      // Load API keys
      const envResp = await endpoints.getEnvVars()
      const env = envResp.data.env_vars || {}

      const keys = {}
      Object.keys(apiKeys).forEach(key => {
        keys[key] = env[key] || ''
      })
      setApiKeys(keys)
    } catch (e) {
      console.error('Failed to load config', e)
    }
  }

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type })
    setTimeout(() => setNotification(null), 5000)
  }

  const handleSaveGithubTokens = async () => {
    if (!githubTokens.trim()) {
      showNotification('Enter at least one GitHub token', 'error')
      return
    }

    setSaving(true)
    try {
      const resp = await endpoints.setGithubTokens({ tokens: githubTokens })

      if (resp.data.status === 'success') {
        showNotification(`Saved ${resp.data.count} GitHub token(s)`, 'success')
        setGithubTokens('')
        loadConfig()
      } else if (resp.data.status === 'warning') {
        showNotification(resp.data.message, 'warning')
        loadConfig()
      }
    } catch (e) {
      showNotification('Failed to save tokens: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleSaveApiKeys = async () => {
    setSaving(true)
    try {
      // Filter non-empty keys
      const updates = {}
      Object.entries(apiKeys).forEach(([key, value]) => {
        if (value && value.trim()) {
          updates[key] = value.trim()
        }
      })

      if (Object.keys(updates).length === 0) {
        showNotification('No API keys to save', 'warning')
        setSaving(false)
        return
      }

      await endpoints.setEnvVars({ env_vars: updates })
      showNotification(`Saved ${Object.keys(updates).length} API key(s)`, 'success')
      loadConfig()
    } catch (e) {
      showNotification('Failed to save API keys: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setSaving(false)
    }
  }

  const toggleKeyVisibility = (key) => {
    setApiKeysVisible(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const getKeyDisplayName = (key) => {
    return key.replace(/_/g, ' ').replace(/API|KEY|ID/g, '').trim()
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Notification */}
      {notification && (
        <div className={clsx(
          'fixed top-4 right-4 z-50 rounded-lg p-4 shadow-lg flex items-center gap-3',
          notification.type === 'success' ? 'bg-green-500/20 border border-green-500/50 text-green-400' :
          notification.type === 'warning' ? 'bg-yellow-500/20 border border-yellow-500/50 text-yellow-400' :
          'bg-red-500/20 border border-red-500/50 text-red-400'
        )}>
          {notification.type === 'success' && <CheckCircle className="w-5 h-5" />}
          {notification.type === 'warning' && <AlertTriangle className="w-5 h-5" />}
          {notification.type === 'error' && <AlertTriangle className="w-5 h-5" />}
          <span>{notification.message}</span>
        </div>
      )}

      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900/50 to-purple-900/50 rounded-lg p-6 border border-blue-500/30">
        <div className="flex items-center gap-3">
          <Key className="w-10 h-10 text-blue-400" />
          <div>
            <h1 className="text-2xl font-bold">API Configuration</h1>
            <p className="text-slate-400 mt-1">Centralized token and API key management</p>
          </div>
        </div>
      </div>

      {/* GitHub Tokens Section */}
      <div className="bg-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Github className="w-5 h-5 text-slate-400" />
            <h2 className="text-lg font-semibold">GitHub Tokens</h2>
          </div>
          {savedTokens.length > 0 && (
            <span className="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-sm">
              {savedTokens.length} token{savedTokens.length > 1 ? 's' : ''} configured
            </span>
          )}
        </div>

        <div className="bg-slate-700/50 rounded p-4">
          <p className="text-sm text-slate-400 mb-3">
            Add GitHub Personal Access Tokens (PAT) for increased rate limits and private repository access.
            Separate multiple tokens with commas for automatic rotation.
          </p>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input
                type={githubTokensVisible ? 'text' : 'password'}
                value={githubTokens}
                onChange={(e) => setGithubTokens(e.target.value)}
                placeholder="ghp_xxxxxxxxxxxx, ghp_yyyyyyyyyyyy, ..."
                className="w-full bg-slate-900 rounded px-4 py-3 pr-12 font-mono text-sm"
              />
              <button
                onClick={() => setGithubTokensVisible(!githubTokensVisible)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-2 hover:bg-slate-700 rounded"
              >
                {githubTokensVisible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <button
              onClick={handleSaveGithubTokens}
              disabled={saving}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 rounded px-6 py-3 font-semibold flex items-center gap-2"
            >
              <Save className="w-4 h-4" />
              Save
            </button>
          </div>
        </div>

        {/* Saved Tokens Display */}
        {savedTokens.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-slate-400">Configured Tokens</h3>
            {savedTokens.map((token, idx) => (
              <div key={idx} className="bg-slate-700 rounded p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="font-mono text-sm">{token}</span>
                </div>
                <span className="text-xs text-slate-400">Token {idx + 1}</span>
              </div>
            ))}
          </div>
        )}

        <div className="text-xs text-slate-500 bg-slate-700/30 rounded p-3">
          <p className="font-semibold mb-1">ℹ️ Token Format</p>
          <p>Valid prefixes: ghp_ (Personal), gho_ (OAuth), ghu_ (User), ghs_ (Server), ghr_ (Refresh), github_pat_ (Fine-grained)</p>
        </div>
      </div>

      {/* API Keys Section */}
      <div className="bg-slate-800 rounded-lg p-6 space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Key className="w-5 h-5 text-slate-400" />
          API Keys
        </h2>

        <div className="space-y-3">
          {Object.entries(apiKeys).map(([key, value]) => (
            <div key={key} className="bg-slate-700/50 rounded p-3">
              <label className="block text-sm text-slate-400 mb-2">{getKeyDisplayName(key)}</label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    type={apiKeysVisible[key] ? 'text' : 'password'}
                    value={value}
                    onChange={(e) => setApiKeys(prev => ({ ...prev, [key]: e.target.value }))}
                    placeholder={`Enter ${getKeyDisplayName(key)}`}
                    className="w-full bg-slate-900 rounded px-4 py-2 pr-12 font-mono text-sm"
                  />
                  <button
                    onClick={() => toggleKeyVisibility(key)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-slate-700 rounded"
                  >
                    {apiKeysVisible[key] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={handleSaveApiKeys}
          disabled={saving}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 rounded px-6 py-3 font-semibold flex items-center justify-center gap-2"
        >
          <Save className="w-4 h-4" />
          {saving ? 'Saving...' : 'Save All API Keys'}
        </button>

        <div className="text-xs text-slate-500 bg-slate-700/30 rounded p-3">
          <p className="font-semibold mb-1">🔒 Security</p>
          <p>All tokens and API keys are stored locally in your .env file and never sent to external servers.</p>
        </div>
      </div>

      {/* HITL Researcher Feedback Stats */}
      <div className="bg-slate-800 rounded-lg p-6 space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-emerald-400" />
          HITL Feedback &amp; Threshold Calibration
        </h2>
        {hitlStats === null ? (
          <p className="text-sm text-slate-500">Loading HITL statistics...</p>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-slate-700/50 rounded p-4 text-center">
                <div className="text-2xl font-black text-emerald-400">{hitlStats.total_feedback ?? 0}</div>
                <div className="text-xs text-slate-500 mt-1 uppercase tracking-widest">Total Feedback</div>
              </div>
              <div className="bg-slate-700/50 rounded p-4 text-center">
                <div className="text-2xl font-black text-green-400">{hitlStats.total_tp ?? 0}</div>
                <div className="text-xs text-slate-500 mt-1 uppercase tracking-widest">True Positives</div>
              </div>
              <div className="bg-slate-700/50 rounded p-4 text-center">
                <div className="text-2xl font-black text-red-400">{hitlStats.total_fp ?? 0}</div>
                <div className="text-xs text-slate-500 mt-1 uppercase tracking-widest">False Positives</div>
              </div>
            </div>
            {hitlStats.per_vuln_type?.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-sm font-semibold text-slate-400">FP Rate by Vuln Type</h3>
                {hitlStats.per_vuln_type.map(item => (
                  <div key={item.vuln_type} className="flex items-center gap-4 bg-slate-700/30 rounded p-3">
                    <span className="text-xs font-mono text-slate-300 w-40 shrink-0">{item.vuln_type}</span>
                    <div className="flex-1 h-2 bg-slate-900 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-red-500 rounded-full"
                        style={{ width: `${Math.min(100, (item.fp_rate ?? 0) * 100)}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono text-slate-400 w-12 text-right">
                      {((item.fp_rate ?? 0) * 100).toFixed(0)}%
                    </span>
                    <span className="text-[10px] text-slate-600">{item.count} samples</span>
                  </div>
                ))}
              </div>
            )}
            {(!hitlStats.per_vuln_type || hitlStats.per_vuln_type.length === 0) && (
              <p className="text-xs text-slate-600 italic">No per-vuln-type data yet — submit findings feedback to calibrate thresholds.</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
