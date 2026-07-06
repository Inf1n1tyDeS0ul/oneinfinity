import React, { useEffect, Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import { useStore } from './store/useStore'
import { useWebSocket } from './hooks/useWebSocket'
import { endpoints } from './utils/api'

// ── Lazy page imports — each page becomes a separate chunk ────────────────────
const Dashboard         = lazy(() => import('./pages/Dashboard'))
const Results           = lazy(() => import('./pages/Results'))
const AttackGraphPage   = lazy(() => import('./pages/AttackGraph'))
const AttackChainsPage  = lazy(() => import('./pages/AttackChains'))
const Targets           = lazy(() => import('./pages/Targets'))
const SystemControl     = lazy(() => import('./pages/SystemControl'))
const ExploitChainViewer= lazy(() => import('./pages/ExploitChainViewer'))
const TrafficExplorer   = lazy(() => import('./pages/TrafficExplorer'))
const BrainDashboard    = lazy(() => import('./pages/BrainDashboard'))
const LiveIntelligence  = lazy(() => import('./pages/LiveIntelligence'))
const SwarmIntelligence = lazy(() => import('./pages/SwarmIntelligence'))
const SystemEvolution   = lazy(() => import('./pages/SystemEvolution'))
const OrchestratorPanel = lazy(() => import('./pages/OrchestratorPanel'))
const MobileWorkspace   = lazy(() => import('./pages/MobileWorkspace'))
const MobileSecurity    = lazy(() => import('./pages/MobileSecurity'))
const MobileAgent       = lazy(() => import('./pages/MobileAgent'))
const BountyHunter      = lazy(() => import('./pages/BountyHunter'))
const SecretDashboard   = lazy(() => import('./pages/SecretDashboard'))
const Fuzzer            = lazy(() => import('./pages/Fuzzer'))
const GodMode           = lazy(() => import('./pages/GodMode'))
const Research          = lazy(() => import('./pages/Research'))
const Tools             = lazy(() => import('./pages/Tools'))
const AIModels          = lazy(() => import('./pages/AIModels'))
const Learning          = lazy(() => import('./pages/Learning'))
const Simulation        = lazy(() => import('./pages/Simulation'))
const Utilities         = lazy(() => import('./pages/Utilities'))
const Reports           = lazy(() => import('./pages/Reports'))
const ReportPreview     = lazy(() => import('./pages/ReportPreview'))
const Infrastructure    = lazy(() => import('./pages/Infrastructure'))
const MCPControl        = lazy(() => import('./pages/MCPControl'))
const AIRedTeam         = lazy(() => import('./pages/AIRedTeam'))
const UnifiedScan       = lazy(() => import('./pages/UnifiedScan'))
const Settings          = lazy(() => import('./pages/Settings'))
const QueueMonitor      = lazy(() => import('./pages/QueueMonitor'))
const SystemHealth      = lazy(() => import('./pages/SystemHealth'))
const PayloadLibrary    = lazy(() => import('./pages/PayloadLibrary'))
const CICDCenter        = lazy(() => import('./pages/CICDCenter'))
const Web3Center        = lazy(() => import('./pages/Web3Center'))
const IDORCenter        = lazy(() => import('./pages/IDORCenter'))
const AdaptivePlanning  = lazy(() => import('./pages/AdaptivePlanning'))
const ToolAnalytics     = lazy(() => import('./pages/ToolAnalytics'))
const Arsenal           = lazy(() => import('./pages/Arsenal'))

// ── Loading fallback ──────────────────────────────────────────────────────────
function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full min-h-[60vh]">
      <div className="flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <span className="text-xs text-gray-500">Loading...</span>
      </div>
    </div>
  )
}

export default function App() {
  const { addLog, setStats, setTargets, setScans, setVulnerabilities, consoleOpen, setConsoleOpen } = useStore()

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault()
        setConsoleOpen(!consoleOpen)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [consoleOpen, setConsoleOpen])

  useWebSocket((entry) => {
    if (entry.type === 'pong') return
    addLog(entry)
    if (entry.is_forensic) {
      const event = new CustomEvent('FORENSIC_SIGNAL', { detail: entry });
      window.dispatchEvent(event);
    }
  })

  useEffect(() => {
    const load = async () => {
      try {
        const [stats, targets, scans, vulns] = await Promise.allSettled([
          endpoints.stats(),
          endpoints.targets(),
          endpoints.scans(),
          endpoints.vulnerabilities(),
        ])
        if (stats.status === 'fulfilled') setStats(stats.value.data)
        if (targets.status === 'fulfilled') setTargets(targets.value.data)
        if (scans.status === 'fulfilled') setScans(scans.value.data)
        if (vulns.status === 'fulfilled') setVulnerabilities(vulns.value.data)
      } catch (e) {
        console.error('Initial load error:', e)
      }
    }
    load()
    const interval = setInterval(() => {
      endpoints.stats().then(r => setStats(r.data)).catch(() => {})
      endpoints.scans().then(r => setScans(r.data)).catch(() => {})
      endpoints.vulnerabilities().then(r => setVulnerabilities(r.data)).catch(() => {})
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <Layout>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"          element={<Dashboard />} />
          <Route path="/targets"            element={<Targets />} />
          <Route path="/results"            element={<Results />} />
          <Route path="/attack-graph"       element={<AttackGraphPage />} />
          <Route path="/attack-chains"      element={<AttackChainsPage />} />
          <Route path="/system"             element={<SystemControl />} />
          <Route path="/traffic"            element={<TrafficExplorer />} />
          <Route path="/fuzzer/:id"         element={<Fuzzer />} />
          <Route path="/chains/:scanId"     element={<ExploitChainViewer />} />
          <Route path="/chains"             element={<ExploitChainViewer />} />
          <Route path="/brain"              element={<BrainDashboard />} />
          <Route path="/intelligence"       element={<LiveIntelligence />} />
          <Route path="/swarm"              element={<SwarmIntelligence />} />
          <Route path="/evolution"          element={<SystemEvolution />} />
          <Route path="/orchestrator"       element={<OrchestratorPanel />} />
          <Route path="/mobile"             element={<Navigate to="/mobile-workspace" replace />} />
          <Route path="/mobile-agent"       element={<Navigate to="/mobile-workspace" replace />} />
          <Route path="/mobile-workspace"   element={<MobileWorkspace />} />
          <Route path="/hunter"             element={<BountyHunter />} />
          <Route path="/secrets"            element={<SecretDashboard />} />
          <Route path="/god-mode"           element={<GodMode />} />
          <Route path="/research"           element={<Research />} />
          <Route path="/tools"              element={<Tools />} />
          <Route path="/ai-ops"             element={<AIModels />} />
          <Route path="/learning"           element={<Learning />} />
          <Route path="/simulation"         element={<Simulation />} />
          <Route path="/utilities"          element={<Utilities />} />
          <Route path="/reports"            element={<Reports />} />
          <Route path="/report-preview/:scanId" element={<ReportPreview />} />
          <Route path="/infrastructure"     element={<Infrastructure />} />
          <Route path="/mcp"                element={<MCPControl />} />
          <Route path="/ai-redteam"         element={<AIRedTeam />} />
          <Route path="/unified-scan"       element={<UnifiedScan />} />
          <Route path="/settings"           element={<Settings />} />
          <Route path="/queue-monitor"      element={<QueueMonitor />} />
          <Route path="/system-health"      element={<SystemHealth />} />
          <Route path="/payloads"           element={<PayloadLibrary />} />
          <Route path="/cicd"               element={<CICDCenter />} />
          <Route path="/web3"               element={<Web3Center />} />
          <Route path="/idor"               element={<IDORCenter />} />
          <Route path="/adaptive-planning"  element={<AdaptivePlanning />} />
          <Route path="/tool-analytics"     element={<ToolAnalytics />} />
          <Route path="/arsenal"            element={<Arsenal />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  )
}
