import React, { useState, useEffect } from 'react'
import api from '../utils/api'

const WAF_OPTIONS = ['generic_waf', 'cloudflare', 'aws', 'akamai', 'imperva']

export default function PayloadLibrary() {
  const [categories, setCategories]   = useState([])
  const [counts, setCounts]           = useState({})
  const [selected, setSelected]       = useState(null)
  const [payloads, setPayloads]       = useState([])
  const [waf, setWaf]                 = useState('generic_waf')
  const [mutations, setMutations]     = useState([])
  const [mutTarget, setMutTarget]     = useState('')
  const [mutPayload, setMutPayload]   = useState('')
  const [mutLoading, setMutLoading]   = useState(false)
  const [wafBypass, setWafBypass]     = useState([])
  const [wafLoading, setWafLoading]   = useState(false)
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)
  const [copied, setCopied]           = useState(null)

  useEffect(() => {
    api.get('/payloads')
      .then(r => {
        setCategories(r.data.categories || [])
        setCounts(r.data.counts || {})
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const selectCategory = async (cat) => {
    setSelected(cat)
    setPayloads([])
    setMutations([])
    setWafBypass([])
    try {
      const r = await api.get(`/payloads/${cat}`)
      setPayloads(r.data.payloads || [])
    } catch (e) {
      setError(e.message)
    }
  }

  const runMutate = async () => {
    if (!mutPayload) return
    setMutLoading(true)
    setMutations([])
    try {
      const r = await api.post('/arsenal/mutate', {
        payload: mutPayload,
        vuln_type: selected || 'xss',
        waf,
      })
      setMutations(r.data.mutations || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setMutLoading(false)
    }
  }

  const loadWafBypass = async () => {
    if (!selected) return
    setWafLoading(true)
    setWafBypass([])
    try {
      const r = await api.get(`/payloads/${selected}/waf-bypass/${waf}`)
      setWafBypass(r.data.variants || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setWafLoading(false)
    }
  }

  const copy = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(text)
    setTimeout(() => setCopied(null), 1500)
  }

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold">Payload Library</h1>
          <p className="text-gray-400 text-sm mt-1">
            Browse payloads by category · generate WAF-bypass mutations via Arsenal
          </p>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded p-3 text-red-300 text-sm mb-6 flex justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">✕</button>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Category Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 text-sm text-gray-400 uppercase tracking-wide">
                Categories
              </div>
              {loading ? (
                <div className="p-4 text-gray-500 text-sm">Loading…</div>
              ) : categories.length === 0 ? (
                <div className="p-4 text-gray-500 text-sm">No payload library found.<br/>
                  <span className="text-xs">Ensure oneinfinity.modules.payloads is available.</span>
                </div>
              ) : (
                <div className="divide-y divide-gray-700">
                  {categories.map(cat => (
                    <button
                      key={cat}
                      onClick={() => selectCategory(cat)}
                      className={`w-full text-left px-4 py-3 flex justify-between items-center hover:bg-gray-700/50 transition-colors ${
                        selected === cat ? 'bg-blue-900/40 text-blue-300' : 'text-gray-300'
                      }`}
                    >
                      <span className="capitalize text-sm">{cat}</span>
                      <span className="text-xs text-gray-500">{counts[cat] || 0}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3 space-y-6">
            {/* WAF selector */}
            <div className="flex items-center gap-4">
              <label className="text-gray-400 text-sm">WAF Target:</label>
              <select
                value={waf}
                onChange={e => setWaf(e.target.value)}
                className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white"
              >
                {WAF_OPTIONS.map(w => <option key={w} value={w}>{w}</option>)}
              </select>
              {selected && (
                <button
                  onClick={loadWafBypass}
                  disabled={wafLoading}
                  className="bg-orange-700 hover:bg-orange-600 text-white text-sm px-4 py-1.5 rounded disabled:opacity-50"
                >
                  {wafLoading ? 'Generating…' : `WAF-Bypass for ${selected}`}
                </button>
              )}
            </div>

            {/* WAF bypass results */}
            {wafBypass.length > 0 && (
              <div className="bg-gray-800/50 rounded-lg p-4 border border-orange-900/50">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-orange-300">WAF-Bypass Variants ({waf})</h3>
                  <button
                    onClick={() => copy(wafBypass.join('\n'))}
                    className="text-xs text-gray-400 hover:text-white"
                  >Copy All</button>
                </div>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {wafBypass.map((p, i) => (
                    <div key={i} className="flex items-center gap-2 group">
                      <code className="flex-1 bg-gray-900 px-3 py-1.5 rounded text-xs text-orange-300 font-mono truncate">{p}</code>
                      <button
                        onClick={() => copy(p)}
                        className="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-white"
                      >{copied === p ? '✓' : 'Copy'}</button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Payload list */}
            {selected && (
              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold capitalize">{selected} Payloads ({payloads.length})</h3>
                  <button
                    onClick={() => copy(payloads.join('\n'))}
                    className="text-xs text-gray-400 hover:text-white"
                  >Copy All</button>
                </div>
                <div className="space-y-1 max-h-72 overflow-y-auto">
                  {payloads.map((p, i) => (
                    <div key={i} className="flex items-center gap-2 group">
                      <code className="flex-1 bg-gray-900 px-3 py-1.5 rounded text-xs text-green-300 font-mono truncate">{p}</code>
                      <button
                        onClick={() => { setMutPayload(p); setMutations([]) }}
                        className="opacity-0 group-hover:opacity-100 text-xs text-blue-400 hover:text-blue-300 whitespace-nowrap"
                      >Mutate</button>
                      <button
                        onClick={() => copy(p)}
                        className="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-white"
                      >{copied === p ? '✓' : 'Copy'}</button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Arsenal Mutation */}
            <div className="bg-gray-800/50 rounded-lg p-4 border border-purple-900/50">
              <h3 className="font-semibold text-purple-300 mb-3">Arsenal WAF-Bypass Mutator</h3>
              <div className="flex gap-3 mb-3">
                <input
                  value={mutPayload}
                  onChange={e => setMutPayload(e.target.value)}
                  placeholder="Enter payload to mutate…"
                  className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono placeholder-gray-600"
                />
                <button
                  onClick={runMutate}
                  disabled={!mutPayload || mutLoading}
                  className="bg-purple-700 hover:bg-purple-600 text-white text-sm px-4 py-2 rounded disabled:opacity-50 whitespace-nowrap"
                >
                  {mutLoading ? 'Mutating…' : 'Mutate'}
                </button>
              </div>
              {mutations.length > 0 && (
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  <div className="text-xs text-gray-400 mb-2">{mutations.length} mutations generated for WAF: {waf}</div>
                  {mutations.map((m, i) => (
                    <div key={i} className="flex items-center gap-2 group">
                      <span className="text-xs text-gray-500 w-32 flex-shrink-0">{m.strategy}</span>
                      <code className="flex-1 bg-gray-900 px-3 py-1 rounded text-xs text-purple-300 font-mono truncate">{m.content}</code>
                      <button
                        onClick={() => copy(m.content)}
                        className="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-white"
                      >{copied === m.content ? '✓' : 'Copy'}</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
