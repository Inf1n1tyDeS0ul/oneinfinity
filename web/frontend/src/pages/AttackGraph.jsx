import React, { useState, useEffect, useRef, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Share2, RefreshCw, Info } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'

const NODE_COLORS = {
  domain:          '#00d4ff',
  host:            '#7c3aed',
  service:         '#10b981',
  endpoint:        '#f59e0b',
  vulnerability:   { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280' },
}

function nodeColor(node) {
  if (node.type === 'vulnerability') {
    return NODE_COLORS.vulnerability[node.severity] || '#6b7280'
  }
  return NODE_COLORS[node.type] || '#94a3b8'
}

export default function AttackGraphPage() {
  const { attackGraph, setAttackGraph, targets, selectedTarget, addNotification } = useStore()
  const [selectedNode, setSelectedNode] = useState(null)
  const [attackPaths, setAttackPaths] = useState([])
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 })
  const containerRef = useRef(null)
  const graphRef = useRef(null)

  const loadGraph = useCallback(async (target) => {
    try {
      const r = await endpoints.attackGraph(target || null)
      setAttackGraph(r.data)
      if (target) {
        const p = await endpoints.graphAttackPaths(target)
        setAttackPaths(p.data?.paths || [])
      } else {
        setAttackPaths([])
      }
    } catch (e) {
      console.error('Graph load failed:', e)
      addNotification(`Failed to load attack graph: ${e.message}`, 'error')
    }
  }, [setAttackGraph, addNotification])

  useEffect(() => {
    loadGraph(selectedTarget)
  }, [selectedTarget, loadGraph])

  useEffect(() => {
    const update = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight,
        })
      }
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [])

  // Transform to force-graph format
  const graphData = {
    nodes: (attackGraph.nodes || []).map(n => ({ ...n })),
    links: (attackGraph.edges || []).map(e => ({
      source: e.source,
      target: e.target,
      label: e.label,
      type: e.type,
    })),
  }

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center justify-between flex-shrink-0">
        <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Share2 size={15} className="text-accent-primary" />
          Attack Graph
        </h1>
        <div className="flex items-center gap-2">
          <select className="select w-48"
            value={selectedTarget || ''}
            onChange={e => loadGraph(e.target.value || null)}>
            <option value="">All Targets</option>
            {targets.map(t => <option key={t.id} value={t.domain}>{t.domain}</option>)}
          </select>
          <button className="btn-secondary flex items-center gap-1.5"
            onClick={() => loadGraph(selectedTarget)}>
            <RefreshCw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-[11px] text-slate-400">
        {[
          { label: 'Domain', color: '#00d4ff' },
          { label: 'Host', color: '#7c3aed' },
          { label: 'Service', color: '#10b981' },
          { label: 'Endpoint', color: '#f59e0b' },
          { label: 'Critical Vuln', color: '#ef4444' },
          { label: 'High Vuln', color: '#f97316' },
          { label: 'Medium Vuln', color: '#f59e0b' },
        ].map(l => (
          <div key={l.label} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: l.color }} />
            {l.label}
          </div>
        ))}
      </div>

      <div className="flex gap-3 flex-1 min-h-0">
        {/* Graph */}
        <div ref={containerRef} className="card flex-1 overflow-hidden relative">
          {graphData.nodes.length === 0 ? (
            <div className="flex items-center justify-center h-64 text-xs text-slate-500">
              No attack graph data. Run a scan to populate the graph.
            </div>
          ) : (
            <ForceGraph2D
              ref={graphRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height - 2}
              backgroundColor="#111827"
              nodeLabel={node => `${node.type}: ${node.label}`}
              nodeColor={nodeColor}
              nodeRelSize={5}
              nodeVal={node => node.type === 'vulnerability' ? 3 : node.type === 'domain' ? 6 : 4}
              linkColor={() => '#1e2d4a'}
              linkWidth={1}
              linkLabel={link => link.label}
              onNodeClick={node => setSelectedNode(node)}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label?.substring(0, 20) || ''
                const fontSize = Math.max(8, 11 / globalScale)
                const r = node.type === 'domain' ? 7 : node.type === 'vulnerability' ? 4 : 5
                ctx.beginPath()
                ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
                ctx.fillStyle = nodeColor(node)
                ctx.fill()
                if (globalScale > 1.5 || node.type === 'domain') {
                  ctx.font = `${fontSize}px JetBrains Mono, monospace`
                  ctx.textAlign = 'center'
                  ctx.textBaseline = 'top'
                  ctx.fillStyle = '#cbd5e1'
                  ctx.fillText(label, node.x, node.y + r + 2)
                }
              }}
            />
          )}
        </div>

        {/* Node detail panel */}
        {selectedNode && (
          <div className="card w-72 flex-shrink-0 overflow-y-auto">
            <div className="card-header">
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <Info size={13} className="text-accent-primary" />
                Node Details
              </div>
              <button className="text-slate-500 hover:text-slate-300 text-xs"
                onClick={() => setSelectedNode(null)}>✕</button>
            </div>
            <div className="p-4 flex flex-col gap-3 text-xs">
              <div>
                <span className="label">Type</span>
                <span style={{ color: nodeColor(selectedNode) }} className="font-medium capitalize">
                  {selectedNode.type}
                </span>
              </div>
              <div>
                <span className="label">Label</span>
                <span className="text-slate-200 break-all">{selectedNode.label}</span>
              </div>
              {selectedNode.severity && (
                <div>
                  <span className="label">Severity</span>
                  <span className={`badge-${selectedNode.severity}`}>{selectedNode.severity}</span>
                </div>
              )}
              {selectedNode.data && Object.entries(selectedNode.data).length > 0 && (
                <div>
                  <span className="label mb-2">Details</span>
                  {Object.entries(selectedNode.data)
                    .filter(([k]) => !['id', 'log_lines'].includes(k))
                    .slice(0, 8)
                    .map(([k, v]) => (
                      <div key={k} className="flex gap-2 mb-1">
                        <span className="text-slate-500 capitalize w-24 flex-shrink-0">{k}:</span>
                        <span className="text-slate-300 break-all">{JSON.stringify(v)?.substring(0, 80)}</span>
                      </div>
                    ))
                  }
                </div>
              )}
              {selectedNode.type === 'vulnerability' && selectedNode.data?.evidence && (
                <button className="btn-danger w-full mt-2">Launch Exploit</button>
              )}
            </div>
          </div>
        )}

        {/* Attack Paths Panel */}
        {!selectedNode && attackPaths.length > 0 && (
          <div className="card w-80 flex-shrink-0 overflow-y-auto">
            <div className="card-header">
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <Share2 size={13} className="text-accent-primary" />
                Simulated Attack Paths
              </div>
            </div>
            <div className="p-4 flex flex-col gap-4 text-xs">
              {attackPaths.sort((a, b) => (b.total_score || 0) - (a.total_score || 0)).map((path, idx) => (
                <div key={idx} className={`p-3 rounded border ${idx === 0 ? 'bg-green-900/20 border-green-500/50' : 'bg-bg-secondary border-white/5'}`}>
                  {idx === 0 && <div className="text-[9px] font-bold text-green-400 uppercase tracking-wider mb-2 flex items-center gap-1">⭐ Most Profitable Path</div>}
                  <div className="font-semibold text-slate-300 mb-1">{path.description || path.chain_description || `Path ${path.path_id}`}</div>
                  <div className="flex flex-col gap-1 text-[10px] text-slate-400 mt-2">
                    <div className="flex justify-between"><span>Impact Score:</span> <span className="text-slate-300 font-mono">{(path.impact_score || 0).toFixed(2)}</span></div>
                    <div className="flex justify-between"><span>Probability:</span> <span className="text-slate-300 font-mono">{(path.exploitability_score || 0).toFixed(2)}</span></div>
                    <div className="flex justify-between font-bold text-cyan-400 mt-1 pt-1 border-t border-white/5"><span>ROI Score:</span> <span>{(path.total_score || 0).toFixed(2)}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
