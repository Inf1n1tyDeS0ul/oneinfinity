import React, { useRef, useCallback, useState, useEffect } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { ZoomIn, ZoomOut, Maximize2, Filter, Download } from 'lucide-react'
import clsx from 'clsx'

const NODE_COLORS = {
  app:        '#06b6d4',   // cyan - mobile app root
  activity:   '#8b5cf6',   // violet - activities
  service:    '#6366f1',   // indigo - services
  provider:   '#f59e0b',   // amber - content providers
  receiver:   '#10b981',   // emerald - broadcast receivers
  api:        '#f97316',   // orange - API endpoints
  server:     '#3b82f6',   // blue - backend servers
  secret:     '#ef4444',   // red - secrets/credentials
  vuln:       '#dc2626',   // deep red - vulnerabilities
  deeplink:   '#a855f7',   // purple - deep links
  websocket:  '#14b8a6',   // teal - websockets
  thirdparty: '#84cc16',   // lime - third-party APIs
}

const NODE_SIZES = {
  app: 14, server: 12, api: 9, activity: 8, service: 8,
  provider: 8, receiver: 7, deeplink: 7, websocket: 7,
  secret: 10, vuln: 11, thirdparty: 8,
}

const LINK_COLORS = {
  calls:    'rgba(249,115,22,0.6)',
  exposes:  'rgba(220,38,38,0.7)',
  contains: 'rgba(99,102,241,0.4)',
  connects: 'rgba(59,130,246,0.5)',
  has_vuln: 'rgba(239,68,68,0.8)',
  uses:     'rgba(139,92,246,0.4)',
}

function buildGraphFromResult(result) {
  const nodes = []
  const links = []
  const seen = new Set()

  function addNode(id, label, type, meta = {}) {
    if (!seen.has(id)) {
      seen.add(id)
      nodes.push({ id, label, type, ...meta })
    }
  }

  function addLink(source, target, type = 'uses', label = '') {
    links.push({ source, target, type, label })
  }

  // App root node
  const appId = 'app_root'
  const appName = result.app_name || 'Mobile App'
  addNode(appId, appName, 'app', { riskScore: result.risk_score || 0 })

  // Static analysis — components
  const staticData = result.static_analysis || {}

  // Exported components
  for (const comp of (staticData.exported_components || [])) {
    const compId = `comp_${comp.name}`
    const compType = comp.component_type || 'activity'
    addNode(compId, comp.name?.split('.').pop() || comp.name, compType, {
      exported: true, fullName: comp.name
    })
    addLink(appId, compId, 'contains')

    for (const dl of (comp.deep_links || [])) {
      const dlId = `dl_${dl}`
      addNode(dlId, dl, 'deeplink', { scheme: dl.split('://')[0] })
      addLink(compId, dlId, 'exposes')
    }
  }

  // All components (non-exported, sample)
  for (const comp of (staticData.components || []).slice(0, 8)) {
    const compId = `comp_${comp.name}`
    if (!seen.has(compId)) {
      const compType = comp.component_type || 'activity'
      addNode(compId, comp.name?.split('.').pop() || comp.name, compType, {
        exported: comp.exported, fullName: comp.name
      })
      addLink(appId, compId, 'contains')
    }
  }

  // API discovery
  const apiData = result.api_discovery || {}

  // Backend servers
  for (const baseUrl of (apiData.base_urls || [])) {
    const serverId = `server_${baseUrl}`
    try {
      const host = new URL(baseUrl).hostname
      addNode(serverId, host, 'server', { url: baseUrl })
      addLink(appId, serverId, 'connects')
    } catch (e) {}
  }

  // API endpoints
  for (const ep of (apiData.endpoints || [])) {
    const epId = `api_${ep.method}_${ep.path}`
    const shortPath = ep.path?.split('/').slice(0, 3).join('/') || ep.path
    addNode(epId, `${ep.method} ${shortPath}`, 'api', {
      method: ep.method, path: ep.path, fullUrl: ep.full_url,
      authRequired: ep.auth_required, fileSource: ep.file_source,
    })
    // Link from component that uses it, or from app
    const sourceId = `server_${apiData.base_urls?.[0]}` || appId
    addLink(seen.has(sourceId) ? sourceId : appId, epId, 'exposes')
  }

  // WebSocket URLs
  for (const ws of (apiData.websocket_urls || [])) {
    const wsId = `ws_${ws}`
    addNode(wsId, ws.replace('wss://', '').replace('ws://', '').split('/')[0], 'websocket', { url: ws })
    addLink(appId, wsId, 'connects')
  }

  // Third-party APIs
  for (const tp of (apiData.third_party_apis || [])) {
    const tpId = `tp_${tp}`
    const [name] = tp.split(':')
    addNode(tpId, name?.trim(), 'thirdparty', { detail: tp })
    addLink(appId, tpId, 'calls')
  }

  // Secrets → link to components/app
  for (const secret of (result.secrets?.findings || []).slice(0, 6)) {
    const sId = `secret_${secret.secret_type}_${Math.random().toString(36).slice(2, 6)}`
    addNode(sId, secret.secret_type, 'secret', {
      severity: secret.severity, file: secret.file_path, preview: secret.value_preview
    })
    addLink(appId, sId, 'has_vuln')
  }

  // Vulnerabilities
  for (const vuln of (result.all_vulnerabilities || []).filter(v => v.severity === 'critical' || v.severity === 'high').slice(0, 5)) {
    const vId = `vuln_${vuln.type}_${Math.random().toString(36).slice(2, 6)}`
    addNode(vId, vuln.type?.replace(/_/g, ' '), 'vuln', {
      severity: vuln.severity, detail: vuln.detail, source: vuln.source
    })
    const targetId = vuln.source === 'api_discovery'
      ? (nodes.find(n => n.type === 'api')?.id || appId)
      : appId
    addLink(targetId, vId, 'has_vuln')
  }

  return { nodes, links }
}

export default function MobileAttackGraph({ result }) {
  const fgRef = useRef()
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })
  const [hovered, setHovered] = useState(null)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    if (result) {
      const data = buildGraphFromResult(result)
      setGraphData(data)
    }
  }, [result])

  const filteredData = React.useMemo(() => {
    if (filter === 'all') return graphData
    return {
      nodes: graphData.nodes.filter(n => n.type === filter || n.type === 'app'),
      links: graphData.links.filter(l => {
        const src = typeof l.source === 'object' ? l.source.id : l.source
        const tgt = typeof l.target === 'object' ? l.target.id : l.target
        return graphData.nodes
          .filter(n => n.type === filter || n.type === 'app')
          .some(n => n.id === src || n.id === tgt)
      }),
    }
  }, [graphData, filter])

  const drawNode = useCallback((node, ctx, globalScale) => {
    const { x, y, type, label, exported } = node
    const size = (NODE_SIZES[type] || 8) / Math.max(1, globalScale * 0.3)
    const color = NODE_COLORS[type] || '#64748b'
    const isHovered = hovered?.id === node.id
    const isSelected = selected?.id === node.id

    // Glow for hovered/selected
    if (isHovered || isSelected) {
      ctx.shadowBlur = 15
      ctx.shadowColor = color
    }

    // Draw circle
    ctx.beginPath()
    ctx.arc(x, y, size, 0, 2 * Math.PI)
    ctx.fillStyle = `${color}33`
    ctx.fill()
    ctx.strokeStyle = color
    ctx.lineWidth = isSelected ? 2.5 : isHovered ? 2 : 1.5
    ctx.stroke()
    ctx.shadowBlur = 0

    // Exported marker
    if (exported) {
      ctx.beginPath()
      ctx.arc(x + size * 0.7, y - size * 0.7, size * 0.35, 0, 2 * Math.PI)
      ctx.fillStyle = '#ef4444'
      ctx.fill()
    }

    // Label
    if (globalScale > 0.6 || isHovered || isSelected) {
      const fontSize = Math.max(8, 11 / globalScale)
      ctx.font = `${fontSize}px JetBrains Mono, monospace`
      ctx.fillStyle = isHovered ? '#ffffff' : '#cbd5e1'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      // Truncate label
      const maxLen = Math.floor(80 / fontSize)
      const displayLabel = (label || '').length > maxLen
        ? (label || '').slice(0, maxLen) + '…'
        : (label || '')
      ctx.fillText(displayLabel, x, y + size + 2)
    }
  }, [hovered, selected])

  const drawLink = useCallback((link, ctx) => {
    const { source, target, type } = link
    if (!source?.x || !target?.x) return
    ctx.strokeStyle = LINK_COLORS[type] || 'rgba(100,116,139,0.3)'
    ctx.lineWidth = type === 'has_vuln' ? 2 : 1
    if (type === 'has_vuln') {
      ctx.setLineDash([4, 3])
    } else {
      ctx.setLineDash([])
    }
    ctx.beginPath()
    ctx.moveTo(source.x, source.y)
    ctx.lineTo(target.x, target.y)
    ctx.stroke()
    ctx.setLineDash([])
  }, [])

  const NODE_TYPES = ['all', 'activity', 'service', 'api', 'server', 'secret', 'vuln', 'deeplink', 'thirdparty']

  const downloadImage = () => {
    if (fgRef.current) {
      const canvas = document.querySelector('.force-graph-container canvas')
      if (canvas) {
        const link = document.createElement('a')
        link.download = 'attack-graph.png'
        link.href = canvas.toDataURL()
        link.click()
      }
    }
  }

  return (
    <div className="flex flex-col h-full gap-2">
      {/* Controls */}
      <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
        <div className="flex items-center gap-1 text-[10px] text-slate-500">
          <Filter size={10} /> Filter:
        </div>
        {NODE_TYPES.map(t => (
          <button key={t}
            className={clsx(
              'px-2 py-0.5 rounded text-[10px] border transition-colors',
              filter === t
                ? 'border-accent-primary/60 text-accent-primary bg-accent-primary/10'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            )}
            onClick={() => setFilter(t)}
            style={t !== 'all' ? { borderColor: `${NODE_COLORS[t]}40`, color: filter === t ? NODE_COLORS[t] : undefined } : undefined}
          >
            {t}
          </button>
        ))}
        <div className="flex-1" />
        <div className="flex gap-1">
          <button className="btn-secondary p-1" onClick={() => fgRef.current?.zoom(1.3)} title="Zoom in"><ZoomIn size={11} /></button>
          <button className="btn-secondary p-1" onClick={() => fgRef.current?.zoom(0.77)} title="Zoom out"><ZoomOut size={11} /></button>
          <button className="btn-secondary p-1" onClick={() => fgRef.current?.zoomToFit(400)} title="Fit"><Maximize2 size={11} /></button>
          <button className="btn-secondary p-1" onClick={downloadImage} title="Export PNG"><Download size={11} /></button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 flex-wrap flex-shrink-0">
        {Object.entries(NODE_COLORS).slice(0, 8).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1 text-[9px] text-slate-400">
            <div className="w-2 h-2 rounded-full" style={{ background: color }} />
            {type}
          </div>
        ))}
        <div className="flex items-center gap-1 text-[9px] text-slate-500">
          <div className="w-3 h-0.5 border-t border-dashed border-red-500/60" />
          vulnerability
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1 relative min-h-0 rounded-lg border border-bg-border overflow-hidden bg-bg-primary">
        {graphData.nodes.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-slate-500">
            No graph data — run full analysis first
          </div>
        ) : (
          <ForceGraph2D
            ref={fgRef}
            graphData={filteredData}
            nodeCanvasObject={drawNode}
            linkCanvasObject={drawLink}
            nodeLabel={n => `${n.type}: ${n.label}`}
            onNodeHover={setHovered}
            onNodeClick={setSelected}
            backgroundColor="#0a0f1a"
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkCurvature={0.1}
            cooldownTicks={80}
            onEngineStop={() => fgRef.current?.zoomToFit(300, 40)}
            width={undefined}
            height={undefined}
          />
        )}

        {/* Selected node info */}
        {selected && (
          <div className="absolute bottom-3 left-3 card p-3 text-xs max-w-xs z-10">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: NODE_COLORS[selected.type] || '#64748b' }} />
              <span className="font-medium text-slate-200">{selected.label}</span>
              <span className="text-[10px] text-slate-500 ml-auto">{selected.type}</span>
            </div>
            {selected.fullName && <div className="text-[10px] text-slate-400 font-mono">{selected.fullName}</div>}
            {selected.url && <div className="text-[10px] text-cyan-400 font-mono">{selected.url}</div>}
            {selected.method && <div className="text-[10px]"><span className="text-orange-400">{selected.method}</span> {selected.path}</div>}
            {selected.severity && <div className="text-[10px] text-red-400">Severity: {selected.severity}</div>}
            {selected.detail && <div className="text-[10px] text-slate-300 mt-1">{selected.detail?.slice(0, 120)}</div>}
            {selected.exported && <div className="text-[10px] text-red-300 mt-1">⚠ Exported (accessible externally)</div>}
            {!selected.authRequired && selected.type === 'api' && (
              <div className="text-[10px] text-red-300 mt-1">⚠ No authentication required</div>
            )}
            <button className="mt-2 text-[10px] text-slate-500 hover:text-slate-300" onClick={() => setSelected(null)}>
              dismiss
            </button>
          </div>
        )}

        {/* Stats overlay */}
        <div className="absolute top-2 right-2 flex gap-1.5">
          <div className="text-[10px] px-2 py-0.5 rounded bg-bg-secondary/80 border border-bg-border text-slate-400">
            {filteredData.nodes.length} nodes
          </div>
          <div className="text-[10px] px-2 py-0.5 rounded bg-bg-secondary/80 border border-bg-border text-slate-400">
            {filteredData.links.length} edges
          </div>
        </div>
      </div>
    </div>
  )
}
