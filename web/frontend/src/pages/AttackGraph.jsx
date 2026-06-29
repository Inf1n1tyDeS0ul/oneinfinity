import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Share2, RefreshCw, Info, Maximize, AlertTriangle } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import HolographicNexus from '../components/Graph/HolographicNexus'

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
  const [riskReport, setRiskReport] = useState(null)
  const [exploiting, setExploiting] = useState(false)
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 })
  const containerRef = useRef(null)
  const graphRef = useRef(null)

  const loadGraph = useCallback(async (target) => {
    try {
      const r = await endpoints.attackGraph(target || null)
      setAttackGraph(r.data)
      if (target) {
        const [pathsRes, riskRes] = await Promise.all([
          endpoints.graphAttackPaths(target),
          fetch(`/api/graph/${encodeURIComponent(target)}/risk-report`).then(r => r.json()).catch(() => null),
        ])
        setAttackPaths(pathsRes.data?.paths || [])
        setRiskReport(riskRes || null)
      } else {
        setAttackPaths([])
        setRiskReport(null)
      }
    } catch (e) {
      console.error('Graph load failed:', e)
      addNotification(`Failed to load attack graph: ${e.message}`, 'error')
    }
  }, [setAttackGraph, addNotification])

  const handleLaunchExploit = async () => {
    if (!selectedNode || selectedNode.type !== 'vulnerability') return
    
    // Attempt to find a database ID for the finding
    const vulnId = selectedNode.data?.finding_db_id || selectedNode.data?.id
    
    if (!vulnId) {
      addNotification('This vulnerability candidate has not been persisted to the database yet. Run a full scan first.', 'warn')
      return
    }

    setExploiting(true)
    try {
      addNotification(`Launching validation swarm for ${selectedNode.label}...`, 'info')
      await endpoints.replayVuln(vulnId)
      addNotification('Exploit validation task successfully dispatched to the swarm.', 'success')
    } catch (e) {
      addNotification(`Failed to launch exploit: ${e.message}`, 'error')
    } finally {
      setExploiting(false)
    }
  }

  const handleNodeClick = useCallback(node => {
    setSelectedNode(node)
    if (graphRef.current) {
      // Aim at node from distance
      const distance = 120;
      const nodeX = node.x || 0;
      const nodeY = node.y || 0;
      const nodeZ = node.z || 0;
      const currentDist = Math.hypot(nodeX, nodeY, nodeZ) || 1;
      const distRatio = 1 + distance / currentDist;
      
      graphRef.current.cameraPosition(
        { x: nodeX * distRatio, y: nodeY * distRatio, z: nodeZ * distRatio }, // new pos
        { x: nodeX, y: nodeY, z: nodeZ }, // lookAt pos
        1500  // transition ms
      );
    }
  }, []);

  useEffect(() => {
    loadGraph(selectedTarget)
  }, [selectedTarget, loadGraph])

  useEffect(() => {
    const update = () => {
      if (containerRef.current) {
        const { offsetWidth, offsetHeight } = containerRef.current;
        if (offsetWidth > 0 && offsetHeight > 0) {
          setDimensions({
            width: offsetWidth,
            height: offsetHeight,
          })
        }
      }
    }
    // Initial update
    update()
    // Small delay to ensure layout has settled
    const timer = setTimeout(update, 100)
    
    window.addEventListener('resize', update)
    return () => {
      window.removeEventListener('resize', update)
      clearTimeout(timer)
    }
  }, [])

  useEffect(() => {
    if (graphRef.current) {
      // Configure simulation for stability and extreme space
      // Increase repulsion and link distance for better clarity
      const fg = graphRef.current;
      fg.d3Force('charge').strength(-1000)
      fg.d3Force('link').distance(150)
      fg.d3Force('center').strength(0.05)
      
      // Auto zoom to fit when data loads
      if (attackGraph.nodes?.length > 0) {
        setTimeout(() => {
          fg.zoomToFit(1000, 150)
        }, 800)
      }
    }
  }, [attackGraph])

  const handleZoomFit = () => {
    if (!graphRef.current) return
    // Pause the physics simulation so it doesn't compete with the camera animation,
    // then zoom asynchronously via rAF to keep the main thread free.
    try { graphRef.current.d3Force('charge').strength(0) } catch (_) {}
    requestAnimationFrame(() => {
      graphRef.current?.zoomToFit(600, 80)
      // Restore charge after animation completes
      setTimeout(() => {
        try { graphRef.current?.d3Force('charge').strength(-1000) } catch (_) {}
      }, 700)
    })
  }

  // Memoize graph data to prevent physics instability on re-renders
  // AND Sort nodes so vulnerabilities are rendered last (on top)
  const graphData = useMemo(() => {
    const nodes = (attackGraph.nodes || []).map(n => ({ ...n }))
    nodes.sort((a, b) => {
      if (a.type === 'vulnerability' && b.type !== 'vulnerability') return 1
      if (a.type !== 'vulnerability' && b.type === 'vulnerability') return -1
      return 0
    })
    return {
      nodes,
      links: (attackGraph.edges || []).map(e => ({
        source: e.source,
        target: e.target,
        label: e.label,
        type: e.type,
      })),
    }
  }, [attackGraph])

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center justify-between flex-shrink-0">
        <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Share2 size={15} className="text-accent-primary" />
          Attack Graph
        </h1>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-bg-secondary p-1 rounded border border-white/5 mr-2">
            <button className="p-1.5 hover:bg-white/10 rounded transition-colors" onClick={handleZoomFit} title="Fit to Screen">
              <Maximize size={14} className="text-slate-400" />
            </button>
          </div>
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

      <div className="flex-1 min-h-0 relative">
        {/* Graph Container - Fills background */}
        <div ref={containerRef} className="absolute inset-0 overflow-hidden">
          {graphData.nodes.length === 0 ? (
            <div className="flex items-center justify-center h-full text-xs text-slate-500">
              No attack graph data. Run a scan to populate the graph.
            </div>
          ) : (
            <HolographicNexus
              ref={graphRef}
              data={graphData}
              onNodeClick={handleNodeClick}
              width={dimensions.width}
              height={dimensions.height}
            />
          )}
        </div>

        {/* HUD Overlay - Top Layer */}
        <div className="absolute inset-0 pointer-events-none flex justify-end p-4 gap-4 overflow-hidden">
          {/* Node detail panel */}
          {selectedNode && (
            <div className="card w-72 flex-shrink-0 overflow-y-auto bg-slate-900/40 backdrop-blur-lg border-white/10 pointer-events-auto">
              <div className="card-header border-white/5">
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
                  <button 
                    className="btn-danger w-full mt-2 flex items-center justify-center gap-2"
                    onClick={handleLaunchExploit}
                    disabled={exploiting}
                  >
                    {exploiting ? (
                      <>
                        <RefreshCw size={13} className="animate-spin" />
                        Launching...
                      </>
                    ) : (
                      'Launch Exploit'
                    )}
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Attack Paths Panel */}
          {!selectedNode && attackPaths.length > 0 && (
            <div className="card w-80 flex-shrink-0 overflow-y-auto bg-slate-900/40 backdrop-blur-lg border-white/10 pointer-events-auto">
              <div className="card-header border-white/5">
                <div className="flex items-center gap-2 text-xs text-slate-300">
                  <Share2 size={13} className="text-accent-primary" />
                  Attack Paths
                </div>
              </div>
              <div className="p-4 flex flex-col gap-4 text-xs">
                {attackPaths.sort((a, b) => (b.total_score || 0) - (a.total_score || 0)).map((path, idx) => (
                  <div key={idx} className={`p-3 rounded border ${idx === 0 ? 'bg-green-900/20 border-green-500/50' : 'bg-bg-secondary/40 border-white/5'}`}>
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

          {/* Risk Report Panel */}
          {!selectedNode && riskReport && riskReport.vuln_nodes > 0 && (
            <div className="card w-56 flex-shrink-0 overflow-y-auto bg-slate-900/40 backdrop-blur-lg border-white/10 pointer-events-auto">
              <div className="card-header border-white/5">
                <div className="flex items-center gap-2 text-xs text-slate-300">
                  <AlertTriangle size={13} className="text-accent-primary" />
                  Risk Summary
                </div>
              </div>
              <div className="p-3 flex flex-col gap-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Overall</span>
                  <span className={`badge-${riskReport.overall_severity || 'info'} font-bold uppercase`}>
                    {riskReport.overall_severity}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Risk Score</span>
                  <span className="text-slate-200 font-mono">{(riskReport.overall_risk_score || 0).toFixed(1)}/10</span>
                </div>
                <div className="border-t border-white/5 pt-2 flex flex-col gap-1 text-[10px]">
                  {riskReport.critical_count > 0 && (
                    <div className="flex justify-between"><span className="text-red-400">Critical</span><span className="font-mono text-red-300">{riskReport.critical_count}</span></div>
                  )}
                  {riskReport.high_count > 0 && (
                    <div className="flex justify-between"><span className="text-orange-400">High</span><span className="font-mono text-orange-300">{riskReport.high_count}</span></div>
                  )}
                  {riskReport.medium_count > 0 && (
                    <div className="flex justify-between"><span className="text-yellow-400">Medium</span><span className="font-mono text-yellow-300">{riskReport.medium_count}</span></div>
                  )}
                </div>
                {riskReport.recommendations?.slice(0, 2).map((rec, i) => (
                  <div key={i} className="text-[10px] text-slate-400 border-t border-white/5 pt-1 mt-1 leading-tight">{rec}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
