import React, { useState } from 'react'
import { Shield, Lock, Unlock, Zap, CheckCircle, XCircle, Loader, AlertTriangle } from 'lucide-react'
import { endpoints } from '../../utils/api'
import { useStore } from '../../store/useStore'
import clsx from 'clsx'

const BYPASS_METHODS = [
  {
    id: 'frida_universal',
    name: 'Frida Universal',
    description: 'Multi-layer SSL bypass using Frida hooks',
    targets: ['TrustManagerImpl', 'OkHttp3 CertificatePinner', 'SSLContext'],
    recommended: true
  },
  {
    id: 'objection',
    name: 'Objection',
    description: 'Objection SSL disable module',
    targets: ['Generic SSL pinning bypass'],
    recommended: false
  }
]

export default function SSLBypassPanel({ appId, packageName, deviceId }) {
  const { addNotification } = useStore()
  const [selectedMethod, setSelectedMethod] = useState('frida_universal')
  const [executing, setExecuting] = useState(false)
  const [result, setResult] = useState(null)
  const [showWarning, setShowWarning] = useState(true)

  const handleBypass = async () => {
    setExecuting(true)
    setResult(null)

    try {
      const response = await endpoints.mobileBypassSSL(appId, {
        method: selectedMethod,
        device_id: deviceId || ''
      })

      setResult(response.data)

      if (response.data.success) {
        addNotification(`SSL bypass successful: ${selectedMethod}`, 'success')
      } else {
        addNotification('SSL bypass failed', 'error')
      }
    } catch (error) {
      console.error('SSL bypass error:', error)
      addNotification(error.response?.data?.detail || 'Bypass failed', 'error')
      setResult({ success: false, error: error.message })
    } finally {
      setExecuting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between p-5 glass-card bg-bg-secondary/30">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-2xl bg-orange-500/10 border border-orange-500/20">
            <Shield size={24} className="text-orange-400" />
          </div>
          <div>
            <h2 className="text-lg font-black text-slate-100 uppercase tracking-tight">SSL Pinning Bypass</h2>
            <p className="text-[10px] text-slate-500 font-mono mt-1">Certificate validation bypass for {packageName}</p>
          </div>
        </div>

        <button
          onClick={handleBypass}
          disabled={executing}
          className={clsx(
            "px-4 py-2 rounded-lg border transition-all text-xs font-bold flex items-center gap-2",
            executing
              ? "bg-slate-700/30 border-slate-700 text-slate-600 cursor-not-allowed"
              : "bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/20 text-orange-400"
          )}
        >
          {executing ? <Loader size={14} className="animate-spin" /> : <Zap size={14} />}
          Execute Bypass
        </button>
      </div>

      {/* Warning Banner */}
      {showWarning && (
        <div className="glass-card p-4 bg-yellow-500/5 border-yellow-500/30 animate-in slide-in-from-top duration-300">
          <div className="flex items-start gap-3">
            <AlertTriangle size={20} className="text-yellow-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-black text-yellow-400 uppercase mb-1">Authorization Required</h3>
              <p className="text-xs text-slate-400 mb-2">
                SSL certificate pinning bypass is an offensive security technique. Only use on:
              </p>
              <ul className="text-[10px] text-slate-500 space-y-1 ml-4 list-disc">
                <li>Applications you own or have written authorization to test</li>
                <li>Bug bounty programs within scope</li>
                <li>Controlled lab environments for security research</li>
              </ul>
            </div>
            <button
              onClick={() => setShowWarning(false)}
              className="text-slate-600 hover:text-slate-400 transition-colors"
            >
              <XCircle size={16} />
            </button>
          </div>
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Method Selection */}
        <div className="glass-card p-4">
          <h3 className="text-xs font-black uppercase text-slate-400 mb-3 tracking-wider">Bypass Method</h3>
          <div className="flex flex-col gap-3">
            {BYPASS_METHODS.map(method => (
              <button
                key={method.id}
                onClick={() => setSelectedMethod(method.id)}
                className={clsx(
                  "text-left p-4 rounded-lg border transition-all",
                  selectedMethod === method.id
                    ? "border-accent-primary bg-accent-primary/10"
                    : "border-bg-border hover:border-slate-600 bg-bg-primary/20"
                )}
              >
                <div className="flex items-start gap-3">
                  <div className={clsx(
                    "p-2 rounded-lg mt-1",
                    selectedMethod === method.id
                      ? "bg-accent-primary/20 text-accent-primary"
                      : "bg-bg-primary text-slate-500"
                  )}>
                    {selectedMethod === method.id ? <Unlock size={16} /> : <Lock size={16} />}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={clsx(
                        "text-sm font-bold",
                        selectedMethod === method.id ? "text-slate-100" : "text-slate-300"
                      )}>
                        {method.name}
                      </span>
                      {method.recommended && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[9px] font-bold uppercase">
                          Recommended
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mb-2">{method.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {method.targets.map((target, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-bg-primary text-slate-600 text-[9px] font-mono"
                        >
                          {target}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </button>
            ))}
          </div>

          {/* How It Works */}
          <div className="mt-4 p-3 rounded-lg bg-bg-primary border border-bg-border">
            <h4 className="text-[10px] font-black uppercase text-slate-500 mb-2 tracking-wider">How It Works</h4>
            <ul className="text-[10px] text-slate-600 space-y-1.5">
              <li className="flex items-start gap-2">
                <span className="text-accent-primary mt-0.5">1.</span>
                <span>Inject Frida script into running app process</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-accent-primary mt-0.5">2.</span>
                <span>Hook Java SSL validation methods</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-accent-primary mt-0.5">3.</span>
                <span>Override certificate checks to always succeed</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-accent-primary mt-0.5">4.</span>
                <span>Intercept HTTPS traffic via mitmproxy</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Result Panel */}
        <div className="glass-card p-4">
          <h3 className="text-xs font-black uppercase text-slate-400 mb-3 tracking-wider">Result</h3>

          {!result && !executing && (
            <div className="flex flex-col items-center justify-center py-12 text-slate-600">
              <Lock size={48} className="mb-3 opacity-20" />
              <p className="text-sm text-center">Execute bypass to see results</p>
            </div>
          )}

          {executing && (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader size={32} className="animate-spin text-accent-primary mb-3" />
              <p className="text-sm text-slate-400">Injecting bypass script...</p>
              <p className="text-[10px] text-slate-600 mt-1">This may take up to 30 seconds</p>
            </div>
          )}

          {result && (
            <div className="animate-in fade-in slide-in-from-bottom-2">
              {/* Status */}
              <div className={clsx(
                "flex items-center gap-3 p-4 rounded-lg mb-4 border",
                result.success
                  ? "bg-emerald-500/10 border-emerald-500/30"
                  : "bg-red-500/10 border-red-500/30"
              )}>
                {result.success ? (
                  <>
                    <CheckCircle size={24} className="text-emerald-400" />
                    <div>
                      <h4 className="text-sm font-black text-emerald-400 uppercase">Bypass Successful</h4>
                      <p className="text-[10px] text-slate-500 mt-1">SSL certificate validation disabled</p>
                    </div>
                  </>
                ) : (
                  <>
                    <XCircle size={24} className="text-red-400" />
                    <div>
                      <h4 className="text-sm font-black text-red-400 uppercase">Bypass Failed</h4>
                      <p className="text-[10px] text-slate-500 mt-1">{result.message || 'Unknown error'}</p>
                    </div>
                  </>
                )}
              </div>

              {/* Details */}
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-bg-primary border border-bg-border">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase">Method</span>
                    <span className="text-xs font-mono text-slate-300">{result.method}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold text-slate-500 uppercase">Package</span>
                    <span className="text-xs font-mono text-slate-300">{result.package_name || packageName}</span>
                  </div>
                </div>

                {/* Findings */}
                {result.findings && result.findings.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold text-slate-400 mb-2 uppercase">Findings</h4>
                    <div className="space-y-2">
                      {result.findings.map((finding, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-bg-primary border border-bg-border">
                          <div className="flex items-center gap-2 mb-1">
                            <Zap size={12} className="text-orange-400" />
                            <span className="text-xs font-bold text-slate-200">{finding.vulnerability}</span>
                            <span className={clsx(
                              "ml-auto text-[10px] font-black uppercase px-2 py-0.5 rounded",
                              finding.severity === 'high' && "bg-orange-500/20 text-orange-400",
                              finding.severity === 'medium' && "bg-yellow-500/20 text-yellow-400"
                            )}>
                              {finding.severity}
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-500 font-mono">{finding.evidence}</p>
                          {finding.confidence && (
                            <div className="mt-2 flex items-center gap-2">
                              <span className="text-[9px] text-slate-600">Confidence:</span>
                              <div className="flex-1 h-1 bg-bg-secondary rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-accent-primary"
                                  style={{ width: `${finding.confidence * 100}%` }}
                                />
                              </div>
                              <span className="text-[9px] text-slate-500 font-mono">
                                {(finding.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Next Steps */}
                {result.success && (
                  <div className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
                    <h4 className="text-[10px] font-black uppercase text-cyan-400 mb-2 tracking-wider">Next Steps</h4>
                    <ul className="text-[10px] text-slate-500 space-y-1">
                      <li>✓ Use TrafficInterceptor to view HTTPS requests</li>
                      <li>✓ Configure mitmproxy cert in device settings</li>
                      <li>✓ Launch app and perform actions</li>
                      <li>✓ All API calls will be decrypted and visible</li>
                    </ul>
                  </div>
                )}

                {/* Error */}
                {result.error && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                    <h4 className="text-xs font-bold text-red-400 mb-2">Error Details</h4>
                    <pre className="text-[10px] text-red-400 font-mono overflow-x-auto">
                      {result.error}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
