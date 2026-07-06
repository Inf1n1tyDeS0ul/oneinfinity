import React, { useEffect, useRef, useState, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { RefreshCw, GitMerge, AlertTriangle, X } from 'lucide-react'
import { endpoints } from '../../utils/api'

const SEV_COLORS = {
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#44aaff',
  info:     '#666666',
}

const TYPE_COLORS = {
  target:        '#00d4ff',
  chain:         '#aa44ff',
  vulnerability: null,   // falls back to SEV_COLORS
  step:          '#444488',
}

function nodeColor(n) {
  if (n.type === 'vulnerability') return SEV_COLORS[n.severity] || '#666'
  return TYPE_COLORS[n.type] || n.color || '#888'
}

/**
 * VulnChainGraph — visualises exploit chains as a directed force graph.
 * Props:
 *   scanId  (string)  — the scan whose chains to display
 *   height  (number)  — canvas height in px (default 340)
 */
export default function VulnChainGraph({ scanId, height = 340 }) {
  const [graphData, setGraphData]   = useState({ nodes: [], links: [] })
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)
  const [selected, setSelected]     = useState(null)
  const [chainCount, setChainCount] = useState(0)
  const graphRef = useRef()

  const fetchChains = useCallback(async () => {
    if (!scanId) return
    setLoading(true)
    setError(null)
    try {
      const r    = await endpoints.scanChains(scanId)
      const data = r.data || {}
      setGraphData({
        nodes: data.nodes || [],
        links: data.links || [],
      })
      setChainCount(data.chain_count ?? 0)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }, [scanId])

  useEffect(() => {
    fetchChains()
  }, [fetchChains])

  const handleNodeClick = useCallback((node) => {
    setSelected(prev => (prev?.id === node.id ? null : node))
  }, [])

  if (!scanId) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm italic">
        Select a scan to view the exploit chain graph
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-2 h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2 text-accent-purple">
          <GitMerge size={16} />
          <span className="text-xs font-bold uppercase tracking-widest">Vulnerability Chain Graph</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono">
            <span>{graphData.nodes.length} nodes</span>
            <span>·</span>
            <span>{graphData.links.length} edges</span>
            {chainCount > 0 && (
              <>
                <span>·</span>
                <span className="text-accent-purple font-bold">{chainCount} chain{chainCount !== 1 ? 's' : ''}</span>
              </>
            )}
          </div>
          <button
            onClick={fetchChains}
            disabled={loading}
            className="p-1 rounded hover:bg-bg-elevated text-slate-500 hover:text-accent-primary transition-colors"
            title="Refresh chain graph"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 text-red-400 text-xs px-2 py-1 bg-red-900/20 rounded border border-red-800/40">
          <AlertTriangle size={12} />
          <span className="flex-1 truncate">{error}</span>
          <button onClick={() => setError(null)}><X size={10} /></button>
        </div>
      )}

      {/* Canvas */}
      <div
        className="relative flex-1 bg-bg-primary/40 rounded-xl border border-bg-border overflow-hidden"
        style={{ minHeight: `${height}px` }}
      >
        {loading ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-sm">
            <RefreshCw size={18} className="animate-spin mr-2" />
            Loading chain graph…
          </div>
        ) : graphData.nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-600 text-sm gap-2">
            <GitMerge size={32} className="opacity-20" />
            <span className="italic">No chain data yet — findings appear as the scan runs</span>
          </div>
        ) : (
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            nodeLabel={n => {
              const sev = n.severity ? ` [${n.severity}]` : ''
              const cnt = n.data?.finding_count ? ` (${n.data.finding_count} findings)` : ''
              return `${n.label}${sev}${cnt}`
            }}
            nodeColor={nodeColor}
            nodeVal={n => n.val || 4}
            linkColor={l => l.color || '#334'}
            linkLabel={l => l.label || ''}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkWidth={1.5}
            onNodeClick={handleNodeClick}
            backgroundColor="transparent"
            width={undefined}
            height={height}
            cooldownTicks={100}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const r    = (node.val || 4) * 1.4
              const col  = nodeColor(node)
              // Glow
              if (node.type !== 'step') {
                ctx.shadowColor = col
                ctx.shadowBlur  = 8
              }
              ctx.beginPath()
              ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
              ctx.fillStyle = col
              ctx.fill()
              ctx.shadowBlur = 0

              if (globalScale > 0.6) {
                const fontSize = Math.max(8, 10 / globalScale)
                ctx.font = `bold ${fontSize}px monospace`
                ctx.textAlign     = 'center'
                ctx.textBaseline  = 'top'
                ctx.fillStyle     = 'rgba(220,220,220,0.88)'
                const label = (node.label || '').substring(0, 18)
                ctx.fillText(label, node.x, node.y + r + 2)
              }
            }}
          />
        )}
      </div>

      {/* Node detail panel */}
      {selected && (
        <div className="p-3 bg-bg-secondary/70 border border-bg-border rounded-xl text-xs animate-fade-in">
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-slate-100 truncate flex-1">{selected.label}</span>
            <button
              onClick={() => setSelected(null)}
              className="text-slate-500 hover:text-white ml-2 flex-shrink-0"
            >
              <X size={12} />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
            <div className="text-slate-500 font-bold uppercase">Type</div>
            <div className="text-slate-300 font-mono">{selected.type}</div>
            {selected.severity && (
              <>
                <div className="text-slate-500 font-bold uppercase">Severity</div>
                <div className="font-mono font-bold" style={{ color: SEV_COLORS[selected.severity] }}>
                  {selected.severity.toUpperCase()}
                </div>
              </>
            )}
            {selected.data?.url && (
              <>
                <div className="text-slate-500 font-bold uppercase">URL</div>
                <div className="text-slate-400 font-mono truncate">{selected.data.url}</div>
              </>
            )}
            {selected.data?.evidence && (
              <>
                <div className="text-slate-500 font-bold uppercase col-span-2">Evidence</div>
                <div className="text-slate-500 font-mono truncate col-span-2">{selected.data.evidence}</div>
              </>
            )}
            {selected.data?.finding_count != null && (
              <>
                <div className="text-slate-500 font-bold uppercase">Findings</div>
                <div className="text-accent-warn font-bold">{selected.data.finding_count}</div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
