import React, { useState, useEffect } from 'react'
import { Cloud, Cpu, RefreshCw, Settings2, DollarSign, CheckCircle2, XCircle, AlertTriangle, Play, Zap } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function MCPControl() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('status')
  const [status, setStatus] = useState(null)
  const [manifest, setManifest] = useState(null)
  const [costTracking, setCostTracking] = useState(null)
  const [integrationStatus, setIntegrationStatus] = useState(null)
  const [loading, setLoading] = useState(false)

  // Tool invocation state
  const [toolDialogOpen, setToolDialogOpen] = useState(false)
  const [selectedTool, setSelectedTool] = useState(null)
  const [toolParams, setToolParams] = useState('')
  const [toolResult, setToolResult] = useState(null)
  const [toolLoading, setToolLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [statusRes, manifestRes, costRes, integrationRes] = await Promise.allSettled([
        endpoints.mcpStatus(),
        endpoints.mcpManifest(),
        endpoints.mcpCostTracking(),
        endpoints.mcpIntegrationStatus(),
      ])
      if (statusRes.status === 'fulfilled') setStatus(statusRes.value.data)
      if (manifestRes.status === 'fulfilled') setManifest(manifestRes.value.data)
      if (costRes.status === 'fulfilled') setCostTracking(costRes.value.data)
      if (integrationRes.status === 'fulfilled') setIntegrationStatus(integrationRes.value.data)
    } catch (err) {
      addNotification('Failed to load MCP data: ' + err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const updateConfig = async (key, value) => {
    try {
      const config = { [key]: value }
      await endpoints.mcpUpdateConfig(config)
      addNotification(`Config updated: ${key} = ${value}`, 'success')
      await load()
    } catch (err) {
      addNotification('Config update failed: ' + err.message, 'error')
    }
  }

  const invokeTool = async () => {
    if (!selectedTool) return

    try {
      setToolLoading(true)
      const params = toolParams ? JSON.parse(toolParams) : {}
      const result = await endpoints.mcpInvokeTool(selectedTool, params)
      setToolResult(result.data)
      addNotification('Tool executed successfully', 'success')
    } catch (err) {
      setToolResult({ error: err.response?.data?.detail || err.message })
      addNotification('Tool invocation failed', 'error')
    } finally {
      setToolLoading(false)
    }
  }

  const openToolDialog = (toolName) => {
    setSelectedTool(toolName)
    setToolParams('')
    setToolResult(null)
    setToolDialogOpen(true)
  }

  const strategyColor = {
    KEEP_BOTH: 'text-green-400',
    ORCHESTRATOR_ONLY: 'text-yellow-400',
    ONEINFINITY_ONLY: 'text-blue-400',
  }

  const budgetPercentage = costTracking?.percentage_used || 0
  const budgetColor = budgetPercentage > 80 ? 'bg-red-500' : budgetPercentage > 50 ? 'bg-yellow-500' : 'bg-green-500'

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <Cpu size={18} className="text-purple-400" />
            MCP Integration Control Panel
          </div>
          <p className="section-subtitle">
            Control AI-Driven mode when OneInfinity is used as MCP tool by Claude CLI, Gemini CLI, or Ollama
          </p>
        </div>
        <button onClick={load} disabled={loading} className="btn-sm btn-secondary">
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button
          onClick={() => setTab('status')}
          className={clsx('tab', tab === 'status' && 'tab-active')}
        >
          Status
        </button>
        <button
          onClick={() => setTab('config')}
          className={clsx('tab', tab === 'config' && 'tab-active')}
        >
          Configuration
        </button>
        <button
          onClick={() => setTab('costs')}
          className={clsx('tab', tab === 'costs' && 'tab-active')}
        >
          Cost Tracking
        </button>
        <button
          onClick={() => setTab('tools')}
          className={clsx('tab', tab === 'tools' && 'tab-active')}
        >
          Tools
        </button>
        <button
          onClick={() => setTab('integration')}
          className={clsx('tab', tab === 'integration' && 'tab-active')}
        >
          Integration
        </button>
      </div>

      {/* Status Tab */}
      {tab === 'status' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">MCP Server Status</h3>
            </div>
            <div className="card-body space-y-4">
              <div className="flex items-center gap-3">
                {status?.enabled ? (
                  <CheckCircle2 className="text-green-400" size={24} />
                ) : (
                  <XCircle className="text-red-400" size={24} />
                )}
                <div>
                  <div className="text-sm text-slate-400">Status</div>
                  <div className="font-medium">{status?.enabled ? 'Enabled' : 'Disabled'}</div>
                </div>
              </div>

              <div className="border-t border-slate-700 pt-4">
                <div className="text-sm text-slate-400 mb-2">Strategy</div>
                <div className={clsx('text-lg font-semibold', strategyColor[status?.strategy])}>
                  {status?.strategy || 'Unknown'}
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  {status?.strategy === 'KEEP_BOTH' && '🔄 Both orchestrator AI and OneInfinity AI active'}
                  {status?.strategy === 'ORCHESTRATOR_ONLY' && '☁️ Only orchestrator AI (Claude/Gemini) active'}
                  {status?.strategy === 'ONEINFINITY_ONLY' && '🔧 Only OneInfinity AI active (standard mode)'}
                </div>
              </div>

              <div className="border-t border-slate-700 pt-4 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Host</span>
                  <span className="font-mono">{status?.server?.host || 'localhost'}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Port</span>
                  <span className="font-mono">{status?.server?.port || 5000}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Tools Available</span>
                  <span className="badge badge-running">{status?.tools_available || 0}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Quick Stats</h3>
            </div>
            <div className="card-body space-y-3">
              <div className="flex items-center gap-3">
                <Cloud className="text-blue-400" size={20} />
                <div className="flex-1">
                  <div className="text-xs text-slate-400">Orchestrator AI Cost</div>
                  <div className="text-lg font-bold text-blue-400">
                    ${costTracking?.costs?.orchestrator_ai?.toFixed(2) || '0.00'}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Cpu className="text-purple-400" size={20} />
                <div className="flex-1">
                  <div className="text-xs text-slate-400">OneInfinity AI Cost</div>
                  <div className="text-lg font-bold text-purple-400">
                    ${costTracking?.costs?.oneinfinity_ai?.toFixed(2) || '0.00'}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <DollarSign className="text-green-400" size={20} />
                <div className="flex-1">
                  <div className="text-xs text-slate-400">Total Cost Today</div>
                  <div className="text-lg font-bold text-green-400">
                    ${costTracking?.total_cost?.toFixed(2) || '0.00'}
                  </div>
                </div>
              </div>

              <div className="border-t border-slate-700 pt-3">
                <div className="text-xs text-slate-400 mb-2">Budget Usage</div>
                <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                  <div
                    className={clsx('h-full transition-all', budgetColor)}
                    style={{ width: `${Math.min(100, budgetPercentage)}%` }}
                  />
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  ${costTracking?.daily_used?.toFixed(2) || '0.00'} / ${costTracking?.daily_limit?.toFixed(2) || '0.00'} ({budgetPercentage.toFixed(1)}%)
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Configuration Tab */}
      {tab === 'config' && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">OneInfinity AI Features</h3>
          </div>
          <div className="card-body space-y-4">
            <p className="text-sm text-slate-400">
              Control which internal AI features remain active in MCP mode
            </p>

            <div className="space-y-3">
              <label className="flex items-center gap-3 p-3 bg-slate-800 rounded cursor-pointer hover:bg-slate-750 transition-colors">
                <input
                  type="checkbox"
                  checked={status?.oneinfinity_ai?.payload_generation || false}
                  onChange={(e) => updateConfig('payload_generation', e.target.checked)}
                  className="w-5 h-5"
                />
                <div className="flex-1">
                  <div className="font-medium">Payload Generation</div>
                  <div className="text-xs text-slate-500">47 SQLi variants, encoding mutations, WAF bypass</div>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3 bg-slate-800 rounded cursor-pointer hover:bg-slate-750 transition-colors">
                <input
                  type="checkbox"
                  checked={status?.oneinfinity_ai?.chain_detection || false}
                  onChange={(e) => updateConfig('chain_detection', e.target.checked)}
                  className="w-5 h-5"
                />
                <div className="flex-1">
                  <div className="font-medium">Exploit Chain Detection</div>
                  <div className="text-xs text-slate-500">Neo4j graph-based path analysis</div>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3 bg-slate-800 rounded cursor-pointer hover:bg-slate-750 transition-colors">
                <input
                  type="checkbox"
                  checked={status?.oneinfinity_ai?.validation_confidence || false}
                  onChange={(e) => updateConfig('validation_confidence', e.target.checked)}
                  className="w-5 h-5"
                />
                <div className="flex-1">
                  <div className="font-medium">Validation Confidence Scoring</div>
                  <div className="text-xs text-slate-500">Rule-based false positive reduction</div>
                </div>
              </label>

              <div className="border-t border-slate-700 pt-4 mt-4">
                <label className="flex items-center gap-3 p-3 bg-slate-800 rounded cursor-pointer hover:bg-slate-750 transition-colors">
                  <input
                    type="checkbox"
                    checked={status?.skip_ai_when_payloads_provided || false}
                    onChange={(e) => updateConfig('skip_ai_when_payloads_provided', e.target.checked)}
                    className="w-5 h-5"
                  />
                  <div className="flex-1">
                    <div className="font-medium">Skip AI When Orchestrator Provides Payloads</div>
                    <div className="text-xs text-slate-500">Avoid redundancy when Claude/Gemini generates payloads</div>
                  </div>
                </label>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cost Tracking Tab */}
      {tab === 'costs' && (
        <div className="space-y-5">
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Daily Budget</h3>
            </div>
            <div className="card-body">
              <div className="w-full bg-slate-700 rounded-full h-4 overflow-hidden mb-3">
                <div
                  className={clsx('h-full transition-all', budgetColor)}
                  style={{ width: `${Math.min(100, budgetPercentage)}%` }}
                />
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Used Today</span>
                <span className="font-mono">${costTracking?.daily_used?.toFixed(2) || '0.00'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Daily Limit</span>
                <span className="font-mono">${costTracking?.daily_limit?.toFixed(2) || '0.00'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Remaining</span>
                <span className="font-mono text-green-400">${costTracking?.remaining?.toFixed(2) || '0.00'}</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="card">
              <div className="card-body text-center">
                <Cloud className="mx-auto mb-3 text-blue-400" size={32} />
                <div className="text-sm text-slate-400">Orchestrator AI</div>
                <div className="text-2xl font-bold text-blue-400">
                  ${costTracking?.costs?.orchestrator_ai?.toFixed(2) || '0.00'}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-body text-center">
                <Cpu className="mx-auto mb-3 text-purple-400" size={32} />
                <div className="text-sm text-slate-400">OneInfinity AI</div>
                <div className="text-2xl font-bold text-purple-400">
                  ${costTracking?.costs?.oneinfinity_ai?.toFixed(2) || '0.00'}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-body text-center">
                <Zap className="mx-auto mb-3 text-yellow-400" size={32} />
                <div className="text-sm text-slate-400">Tool Costs</div>
                <div className="text-2xl font-bold text-yellow-400">
                  ${costTracking?.costs?.tools?.toFixed(2) || '0.00'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tools Tab */}
      {tab === 'tools' && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Available MCP Tools</h3>
          </div>
          <div className="card-body">
            <p className="text-sm text-slate-400 mb-4">
              Click tool name to invoke manually from UI
            </p>
            <div className="space-y-2">
              {manifest?.tools?.map((tool) => (
                <div key={tool.name} className="flex items-center justify-between p-3 bg-slate-800 rounded hover:bg-slate-750 transition-colors">
                  <div className="flex-1">
                    <div className="font-mono text-sm text-purple-400">{tool.name}</div>
                    <div className="text-xs text-slate-500">{tool.description}</div>
                  </div>
                  <button
                    onClick={() => openToolDialog(tool.name)}
                    className="btn-xs btn-secondary"
                  >
                    <Play size={14} />
                    Invoke
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Integration Tab */}
      {tab === 'integration' && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Integration Status</h3>
          </div>
          <div className="card-body space-y-4">
            <p className="text-sm text-slate-400">
              Check if OneInfinity is registered with AI CLIs
            </p>

            <div className="space-y-3">
              <div className="flex items-start gap-3 p-3 bg-slate-800 rounded">
                {integrationStatus?.claude_cli?.config_exists ? (
                  <CheckCircle2 className="text-green-400 mt-1" size={20} />
                ) : (
                  <XCircle className="text-red-400 mt-1" size={20} />
                )}
                <div className="flex-1">
                  <div className="font-medium">Claude CLI</div>
                  <div className="text-xs text-slate-500 font-mono">{integrationStatus?.claude_cli?.config_path}</div>
                  <div className="text-xs text-slate-400 mt-1">
                    Recommended: {integrationStatus?.claude_cli?.recommended_models?.join(', ')}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 bg-slate-800 rounded">
                {integrationStatus?.gemini_cli?.config_exists ? (
                  <CheckCircle2 className="text-green-400 mt-1" size={20} />
                ) : (
                  <XCircle className="text-red-400 mt-1" size={20} />
                )}
                <div className="flex-1">
                  <div className="font-medium">Gemini CLI</div>
                  <div className="text-xs text-slate-500 font-mono">{integrationStatus?.gemini_cli?.config_path}</div>
                  <div className="text-xs text-slate-400 mt-1">
                    Recommended: {integrationStatus?.gemini_cli?.recommended_models?.join(', ')}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 bg-slate-800 rounded">
                {integrationStatus?.ollama?.config_exists ? (
                  <CheckCircle2 className="text-green-400 mt-1" size={20} />
                ) : (
                  <XCircle className="text-red-400 mt-1" size={20} />
                )}
                <div className="flex-1">
                  <div className="font-medium">Ollama</div>
                  <div className="text-xs text-slate-500 font-mono">{integrationStatus?.ollama?.config_path}</div>
                  <div className="text-xs text-slate-400 mt-1">
                    Recommended: {integrationStatus?.ollama?.recommended_models?.join(', ')}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tool Invocation Modal */}
      {toolDialogOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setToolDialogOpen(false)}>
          <div className="card w-full max-w-2xl m-4" onClick={(e) => e.stopPropagation()}>
            <div className="card-header">
              <h3 className="card-title">Invoke Tool: {selectedTool}</h3>
            </div>
            <div className="card-body space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-2">Parameters (JSON)</label>
                <textarea
                  value={toolParams}
                  onChange={(e) => setToolParams(e.target.value)}
                  placeholder='{"target": "example.com", "vuln_types": ["xss", "sqli"]}'
                  className="w-full h-32 p-3 bg-slate-800 border border-slate-700 rounded font-mono text-sm"
                />
              </div>

              {toolLoading && (
                <div className="flex items-center gap-2 text-slate-400">
                  <RefreshCw size={16} className="animate-spin" />
                  <span>Executing...</span>
                </div>
              )}

              {toolResult && (
                <div>
                  <div className="text-sm text-slate-400 mb-2">Result:</div>
                  <pre className="p-3 bg-slate-900 border border-slate-700 rounded text-xs overflow-auto max-h-96">
                    {JSON.stringify(toolResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t border-slate-700">
              <button onClick={() => setToolDialogOpen(false)} className="btn-secondary">
                Close
              </button>
              <button onClick={invokeTool} disabled={toolLoading} className="btn-primary">
                <Play size={16} />
                Invoke
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
