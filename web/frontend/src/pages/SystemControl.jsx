import React, { useState, useEffect } from 'react'
import { endpoints } from '../utils/api'

export default function SystemControl() {
  const [safety, setSafety] = useState({ safe_mode: true, rate_limit_delay: 1.0 })
  const [waf, setWaf] = useState({ detections: 0, mutations: 0, successes: 0, by_type: {} })
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [s, w] = await Promise.all([
        endpoints.getSafetyConfig(),
        endpoints.getWafStats()
      ])
      setSafety(s.data)
      setWaf(w.data)
    } catch (e) {
      console.error('Load failed', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const int = setInterval(load, 5000)
    return () => clearInterval(int)
  }, [])

  const toggleSafeMode = async () => {
    try {
      const next = !safety.safe_mode
      await endpoints.updateSafetyConfig({ safe_mode: next })
      setSafety({ ...safety, safe_mode: next })
    } catch (e) { alert('Update failed') }
  }

  const updateRateLimit = async (val) => {
    try {
      const delay = parseFloat(val)
      await endpoints.updateSafetyConfig({ rate_limit_delay: delay })
      setSafety({ ...safety, rate_limit_delay: delay })
    } catch (e) { alert('Update failed') }
  }

  if (loading) return <div className="p-8">Loading system state...</div>

  return (
    <div className="p-8 space-y-8">
      <header>
        <h1 className="text-2xl font-bold">System Control & Telemetry</h1>
        <p className="text-gray-400">Manage platform guardrails and observe intelligent evasion stats.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Safety Guard */}
        <section className="bg-gray-900 p-6 rounded-lg border border-gray-800">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">🛡️</span> Safety Guard
          </h2>
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Safe Mode</p>
                <p className="text-sm text-gray-400">Prevents destructive payloads (rm, drop, etc.)</p>
              </div>
              <button 
                onClick={toggleSafeMode}
                className={`px-4 py-2 rounded font-bold ${safety.safe_mode ? 'bg-green-600' : 'bg-red-600'}`}
              >
                {safety.safe_mode ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>
            
            <div className="space-y-2">
              <label className="block font-medium">Rate Limit Delay (seconds)</label>
              <input 
                type="range" min="0.1" max="5.0" step="0.1" 
                value={safety.rate_limit_delay}
                onChange={(e) => updateRateLimit(e.target.value)}
                className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
              />
              <div className="flex justify-between text-xs text-gray-500">
                <span>0.1s (Fast)</span>
                <span className="text-blue-400 font-bold">{safety.rate_limit_delay}s</span>
                <span>5.0s (Stealth)</span>
              </div>
            </div>
          </div>
        </section>

        {/* API Authentication */}
        <section className="bg-gray-900 p-6 rounded-lg border border-gray-800">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">🔑</span> API Authentication
          </h2>
          <div className="space-y-4">
            <p className="text-sm text-gray-400">
              The framework uses an API key for authentication. If the frontend is unable to fetch it automatically, you can set it here.
            </p>
            <div>
              <label className="block text-sm font-medium mb-1.5">OneInfinity API Key</label>
              <div className="flex gap-2">
                <input
                  type="password"
                  defaultValue={localStorage.getItem('oneinfinity_api_key') || ''}
                  placeholder="Paste your API key here"
                  id="api-key-input"
                  className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={() => {
                    const val = document.getElementById('api-key-input').value.trim()
                    if (val) {
                      localStorage.setItem('oneinfinity_api_key', val)
                      alert('API key saved! Reload the page to apply.')
                      window.location.reload()
                    } else {
                      localStorage.removeItem('oneinfinity_api_key')
                      alert('API key cleared!')
                    }
                  }}
                  className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-bold text-sm"
                >
                  SAVE
                </button>
              </div>
            </div>
            <p className="text-[10px] text-gray-500 italic">
              Key is stored in browser localStorage. You can find it in the terminal where you started the backend if you didn't set ONEINFINITY_API_KEY.
            </p>
          </div>
        </section>

        {/* WAF Telemetry */}
        <section className="bg-gray-900 p-6 rounded-lg border border-gray-800">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">📡</span> WAF Evasion Stats
          </h2>
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="text-center p-3 bg-gray-800 rounded">
              <p className="text-xs text-gray-400 uppercase">Blocks</p>
              <p className="text-2xl font-bold text-orange-400">{waf.detections}</p>
            </div>
            <div className="text-center p-3 bg-gray-800 rounded">
              <p className="text-xs text-gray-400 uppercase">Mutations</p>
              <p className="text-2xl font-bold text-blue-400">{waf.mutations}</p>
            </div>
            <div className="text-center p-3 bg-gray-800 rounded">
              <p className="text-xs text-gray-400 uppercase">Bypasses</p>
              <p className="text-2xl font-bold text-green-400">{waf.successes}</p>
            </div>
          </div>

          <div>
            <p className="text-sm font-medium mb-2">Detections by Type</p>
            {Object.keys(waf.by_type).length === 0 ? (
              <p className="text-xs text-gray-500 italic">No WAF detections recorded in this session.</p>
            ) : (
              <div className="space-y-2">
                {Object.entries(waf.by_type).map(([name, count]) => (
                  <div key={name} className="flex justify-between items-center text-sm">
                    <span className="text-gray-300">{name}</span>
                    <span className="bg-gray-800 px-2 py-0.5 rounded text-blue-300 font-mono">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Health / System Status */}
      <section className="bg-gray-900 p-6 rounded-lg border border-gray-800">
        <h2 className="text-xl font-semibold mb-4">System Health</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <HealthItem label="API Layer" status="Online" color="text-green-400" />
          <HealthItem label="Event Bus" status="Active" color="text-green-400" />
          <HealthItem label="Traffic Engine" status="Capturing" color="text-blue-400" />
          <HealthItem label="Graph Brain" status="Thinking" color="text-purple-400" />
        </div>
      </section>
    </div>
  )
}

function HealthItem({ label, status, color }) {
  return (
    <div className="p-4 bg-gray-800 rounded border border-gray-700">
      <p className="text-xs text-gray-400 uppercase mb-1">{label}</p>
      <div className="flex items-center">
        <div className={`w-2 h-2 rounded-full mr-2 bg-current ${color}`} />
        <p className={`font-bold ${color}`}>{status}</p>
      </div>
    </div>
  )
}
