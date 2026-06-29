import React, { useState, useEffect, useRef } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Download, Zap, AlertTriangle, TrendingUp, Eye, X } from 'lucide-react'
import clsx from 'clsx'

/**
 * Attack Chain Viewer Component
 *
 * Visualizes detected attack chains as interactive force-directed graph.
 * Features:
 * - Color-coded nodes by severity
 * - Chain highlighting on hover
 * - Details panel on click
 * - Export functionality
 */

const AttackChainViewer = ({ target, chains = [], width = 800, height = 600, onTestChain }) => {
  const graphRef = useRef()
  const [selectedChain, setSelectedChain] = useState(null)
  const [hoveredChain, setHoveredChain] = useState(null)
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })

  // Convert chains to graph data
  useEffect(() => {
    if (!chains || chains.length === 0) {
      setGraphData({ nodes: [], links: [] })
      return
    }

    const nodes = []
    const links = []
    const nodeMap = new Map()

    chains.forEach((chain, chainIdx) => {
      chain.nodes.forEach((node, nodeIdx) => {
        if (!nodeMap.has(node.id)) {
          nodeMap.set(node.id, {
            id: node.id,
            label: node.type || node.id,
            type: 'vulnerability',
            severity: node.severity,
            confidence: node.confidence,
            cvss: node.cvss,
            chainId: chain.chain_id,
            isEntry: nodeIdx === 0,
            isObjective: nodeIdx === chain.nodes.length - 1,
          })
          nodes.push(nodeMap.get(node.id))
        }
      })

      chain.edges.forEach(edge => {
        links.push({
          source: edge.from,
          target: edge.to,
          chainId: chain.chain_id,
        })
      })
    })

    setGraphData({ nodes, links })
  }, [chains])

  // Node color by severity
  const getNodeColor = (node) => {
    if (!node) return '#64748b'

    // Highlight if chain selected/hovered
    const activeChain = selectedChain || hoveredChain
    if (activeChain && node.chainId !== activeChain.chain_id) {
      return '#1e293b' // Dim non-selected
    }

    if (node.isEntry) return '#10b981' // Green for entry
    if (node.isObjective) return '#ef4444' // Red for objective

    // Color by severity
    switch (node.severity) {
      case 'critical': return '#dc2626'
      case 'high': return '#f97316'
      case 'medium': return '#f59e0b'
      case 'low': return '#3b82f6'
      default: return '#64748b'
    }
  }

  // Link color
  const getLinkColor = (link) => {
    const activeChain = selectedChain || hoveredChain
    if (activeChain && link.chainId !== activeChain.chain_id) {
      return 'rgba(30, 41, 59, 0.3)'
    }
    return 'rgba(59, 130, 246, 0.6)'
  }

  // Handle node click
  const handleNodeClick = (node) => {
    const chain = chains.find(c => c.chain_id === node.chainId)
    setSelectedChain(chain)
  }

  // Export chain as JSON
  const exportChain = (chain) => {
    const dataStr = JSON.stringify(chain, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `chain_${chain.chain_id}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  if (!chains || chains.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle size={48} className="mx-auto text-slate-600 mb-4" />
          <p className="text-slate-400">No attack chains detected for {target}</p>
          <p className="text-xs text-slate-600 mt-2">
            Run a scan to discover potential attack paths
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      {/* Graph Canvas */}
      <div className="absolute inset-0">
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          width={width}
          height={height}
          backgroundColor="#0f172a"
          nodeLabel={node => `${node.type}: ${node.label} (${node.severity})`}
          nodeColor={getNodeColor}
          linkColor={getLinkColor}
          linkDirectionalArrowLength={6}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={hoveredChain || selectedChain ? 2 : 0}
          linkDirectionalParticleSpeed={0.006}
          linkDirectionalParticleWidth={2}
          nodeRelSize={8}
          onNodeClick={handleNodeClick}
          onNodeHover={node => {
            if (node) {
              const chain = chains.find(c => c.chain_id === node.chainId)
              setHoveredChain(chain)
            } else {
              setHoveredChain(null)
            }
          }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.label
            const fontSize = 12 / globalScale
            ctx.font = `${fontSize}px monospace`
            const textWidth = ctx.measureText(label).width
            const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.4)

            // Draw node circle
            ctx.fillStyle = getNodeColor(node)
            ctx.beginPath()
            ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI, false)
            ctx.fill()

            // Pulsing effect for objectives
            if (node.isObjective) {
              ctx.strokeStyle = '#ef4444'
              ctx.lineWidth = 2 / globalScale
              const pulse = Math.abs(Math.sin(Date.now() / 500))
              ctx.beginPath()
              ctx.arc(node.x, node.y, 8 + pulse * 4, 0, 2 * Math.PI, false)
              ctx.stroke()
            }

            // Draw label
            ctx.fillStyle = 'rgba(255, 255, 255, 0.9)'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillText(label, node.x, node.y + 16)
          }}
        />
      </div>

      {/* Chain Legend */}
      <div className="absolute top-4 left-4 bg-slate-900/90 backdrop-blur-sm rounded-lg p-4 border border-slate-700/50 shadow-lg">
        <h3 className="text-xs font-semibold text-slate-300 mb-3 uppercase tracking-wider">
          Chains ({chains.length})
        </h3>
        <div className="space-y-2">
          {chains.map((chain, idx) => (
            <button
              key={chain.chain_id}
              onClick={() => setSelectedChain(chain)}
              onMouseEnter={() => setHoveredChain(chain)}
              onMouseLeave={() => setHoveredChain(null)}
              className={clsx(
                'w-full text-left p-2 rounded transition-all',
                selectedChain?.chain_id === chain.chain_id
                  ? 'bg-cyan-500/20 border border-cyan-500/50'
                  : 'bg-slate-800/50 border border-slate-700/30 hover:bg-slate-700/50'
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-mono text-slate-300">
                  Chain {idx + 1}
                </span>
                <span className={clsx(
                  'text-[10px] px-1.5 py-0.5 rounded font-mono',
                  chain.exploitability >= 0.7 ? 'bg-red-500/20 text-red-400' :
                  chain.exploitability >= 0.4 ? 'bg-orange-500/20 text-orange-400' :
                  'bg-slate-600/20 text-slate-400'
                )}>
                  {(chain.exploitability * 100).toFixed(0)}%
                </span>
              </div>
              <div className="flex items-center gap-1 mt-1">
                <span className="text-[10px] text-slate-500">{chain.length} steps</span>
                <span className="text-[10px] text-slate-600">→</span>
                <span className="text-[10px] text-cyan-400">{chain.objective}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Details Panel */}
      {selectedChain && (
        <div className="absolute top-4 right-4 w-96 bg-slate-900/95 backdrop-blur-sm rounded-lg border border-slate-700/50 shadow-2xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-slate-700/50">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Chain Details</h3>
            </div>
            <button
              onClick={() => setSelectedChain(null)}
              className="p-1 rounded hover:bg-slate-800 transition-colors"
            >
              <X size={16} className="text-slate-400" />
            </button>
          </div>

          {/* Content */}
          <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
            {/* Metrics */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                  Exploitability
                </div>
                <div className="text-2xl font-bold text-cyan-400">
                  {(selectedChain.exploitability * 100).toFixed(0)}%
                </div>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                  Confidence
                </div>
                <div className="text-2xl font-bold text-emerald-400">
                  {(selectedChain.confidence * 100).toFixed(0)}%
                </div>
              </div>
            </div>

            {/* CVSS Escalation */}
            <div className="bg-slate-800/50 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-2">
                <TrendingUp size={14} className="text-orange-400" />
                <span className="text-[10px] text-slate-500 uppercase tracking-wider">
                  CVSS Escalation
                </span>
              </div>
              <div className="text-xl font-bold text-orange-400">
                +{selectedChain.cvss_escalation.toFixed(1)}
              </div>
            </div>

            {/* Attack Steps */}
            <div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-3">
                Attack Path ({selectedChain.length} steps)
              </div>
              <div className="space-y-2">
                {selectedChain.nodes.map((node, idx) => (
                  <div key={node.id}>
                    <div className="flex items-start gap-3">
                      <div className={clsx(
                        'flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold',
                        idx === 0 ? 'bg-emerald-500/20 text-emerald-400' :
                        idx === selectedChain.nodes.length - 1 ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-300'
                      )}>
                        {idx + 1}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-mono text-slate-300">{node.type}</span>
                          <span className={clsx(
                            'text-[10px] px-2 py-0.5 rounded font-semibold',
                            node.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                            node.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            node.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-blue-500/20 text-blue-400'
                          )}>
                            {node.severity}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          CVSS: {node.cvss.toFixed(1)} | Confidence: {(node.confidence * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                    {idx < selectedChain.nodes.length - 1 && (
                      <div className="ml-3 my-1 border-l-2 border-dashed border-slate-700 h-4" />
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Objective */}
            <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-lg p-3 border border-cyan-500/20">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                Objective
              </div>
              <div className="text-sm font-semibold text-cyan-400 uppercase">
                {selectedChain.objective}
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-2">
              <button
                onClick={() => exportChain(selectedChain)}
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors border border-slate-700"
              >
                <Download size={14} className="text-slate-400" />
                <span className="text-xs text-slate-300">Export JSON</span>
              </button>
              {onTestChain && (
                <button
                  onClick={() => onTestChain(selectedChain)}
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 rounded-lg transition-colors border border-cyan-500/50"
                >
                  <Eye size={14} className="text-cyan-400" />
                  <span className="text-xs text-cyan-300">Test Chain</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AttackChainViewer
