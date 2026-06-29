import React, { useState, useEffect } from 'react'
import { Zap, RefreshCw, AlertCircle, TrendingUp } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import AttackChainViewer from '../components/AttackChainViewer'

/**
 * Attack Chains Page
 *
 * Displays detected attack chains for selected target.
 * Uses GraphChainDetector backend API.
 */

export default function AttackChainsPage() {
  const { selectedTarget, targets, addNotification } = useStore()
  const [chains, setChains] = useState([])
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState({ chain_count: 0, high_risk_chains: 0 })
  const [dimensions, setDimensions] = useState({ width: 1000, height: 600 })

  // Load chains for target
  const loadChains = async (target) => {
    if (!target) {
      setChains([])
      setStats({ chain_count: 0, high_risk_chains: 0 })
      return
    }

    setLoading(true)
    try {
      const response = await endpoints.getAttackChains(target)
      const data = response.data

      setChains(data.chains || [])
      setStats({
        chain_count: data.chain_count || 0,
        high_risk_chains: data.high_risk_chains || 0,
      })
    } catch (err) {
      console.error('Failed to load chains:', err)
      addNotification(`Failed to load attack chains: ${err.message}`, 'error')
      setChains([])
    } finally {
      setLoading(false)
    }
  }

  // Handle test chain (validation trigger)
  const handleTestChain = async (chain) => {
    addNotification(`Testing chain ${chain.chain_id}...`, 'info')
    // TODO: Implement validation trigger via API
    // This would call ValidationOrchestrator for each node in chain
  }

  // Load on mount and target change
  useEffect(() => {
    loadChains(selectedTarget)
  }, [selectedTarget])

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      setDimensions({
        width: window.innerWidth - 350, // Account for sidebar
        height: window.innerHeight - 250, // Account for header + stats
      })
    }

    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [])

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-3">
          <Zap size={20} className="text-cyan-400" />
          <div>
            <h1 className="text-lg font-semibold text-slate-200">Attack Chains</h1>
            <p className="text-xs text-slate-500">
              Multi-hop attack paths detected by chain analyzer
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            className="select w-56"
            value={selectedTarget || ''}
            onChange={(e) => loadChains(e.target.value || null)}
          >
            <option value="">Select Target</option>
            {targets.map((t) => (
              <option key={t.id} value={t.domain}>
                {t.domain}
              </option>
            ))}
          </select>

          <button
            className="btn-secondary flex items-center gap-2"
            onClick={() => loadChains(selectedTarget)}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {selectedTarget && (
        <div className="grid grid-cols-3 gap-4 flex-shrink-0">
          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                  Total Chains
                </div>
                <div className="text-3xl font-bold text-slate-200">
                  {stats.chain_count}
                </div>
              </div>
              <Zap size={32} className="text-cyan-400 opacity-50" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                  High Risk
                </div>
                <div className="text-3xl font-bold text-orange-400">
                  {stats.high_risk_chains}
                </div>
              </div>
              <AlertCircle size={32} className="text-orange-400 opacity-50" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                  Avg Exploitability
                </div>
                <div className="text-3xl font-bold text-emerald-400">
                  {chains.length > 0
                    ? (
                        (chains.reduce((sum, c) => sum + c.exploitability, 0) / chains.length) *
                        100
                      ).toFixed(0)
                    : 0}
                  %
                </div>
              </div>
              <TrendingUp size={32} className="text-emerald-400 opacity-50" />
            </div>
          </div>
        </div>
      )}

      {/* Graph Viewer */}
      <div className="card flex-1 min-h-0 p-4">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <RefreshCw size={32} className="animate-spin text-cyan-400" />
          </div>
        ) : !selectedTarget ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <Zap size={48} className="mx-auto text-slate-600 mb-4" />
              <p className="text-slate-400">Select a target to view attack chains</p>
              <p className="text-xs text-slate-600 mt-2">
                Chains are automatically detected when you run a scan
              </p>
            </div>
          </div>
        ) : (
          <AttackChainViewer
            target={selectedTarget}
            chains={chains}
            width={dimensions.width}
            height={dimensions.height}
            onTestChain={handleTestChain}
          />
        )}
      </div>
    </div>
  )
}
