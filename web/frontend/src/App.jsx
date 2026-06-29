import React, { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Results from './pages/Results'
import AttackGraphPage from './pages/AttackGraph'
import AttackChainsPage from './pages/AttackChains'
import Targets from './pages/Targets'
import { useStore } from './store/useStore'
import { useWebSocket } from './hooks/useWebSocket'
import { endpoints } from './utils/api'

import SystemControl from './pages/SystemControl'
import ExploitChainViewer from './pages/ExploitChainViewer'
import TrafficExplorer from './pages/TrafficExplorer'
import BrainDashboard from './pages/BrainDashboard'
import LiveIntelligence from './pages/LiveIntelligence'
import SwarmIntelligence from './pages/SwarmIntelligence'
import SystemEvolution from './pages/SystemEvolution'
import OrchestratorPanel from './pages/OrchestratorPanel'
import MobileWorkspace from './pages/MobileWorkspace'
import MobileSecurity from './pages/MobileSecurity'
import MobileAgent from './pages/MobileAgent'
import BountyHunter from './pages/BountyHunter'
import SecretDashboard from './pages/SecretDashboard'
import Fuzzer from './pages/Fuzzer'

// New pages
import GodMode from './pages/GodMode'
import Research from './pages/Research'
import Tools from './pages/Tools'
import AIModels from './pages/AIModels'
import Learning from './pages/Learning'
import Simulation from './pages/Simulation'
import Utilities from './pages/Utilities'
import Reports from './pages/Reports'
import ReportPreview from './pages/ReportPreview'
import Infrastructure from './pages/Infrastructure'
import MCPControl from './pages/MCPControl'
import AIRedTeam from './pages/AIRedTeam'
import UnifiedScan from './pages/UnifiedScan'
import Settings from './pages/Settings'
import QueueMonitor from './pages/QueueMonitor'
import SystemHealth from './pages/SystemHealth'
import PayloadLibrary from './pages/PayloadLibrary'
import CICDCenter from './pages/CICDCenter'
import Web3Center from './pages/Web3Center'
import IDORCenter from './pages/IDORCenter'
import AdaptivePlanning from './pages/AdaptivePlanning'
import ToolAnalytics from './pages/ToolAnalytics'

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
    
    // Dispatch forensic signals to window event bus
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
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard"      element={<Dashboard />} />
        <Route path="/targets"        element={<Targets />} />
        <Route path="/results"        element={<Results />} />
        <Route path="/attack-graph"   element={<AttackGraphPage />} />
        <Route path="/attack-chains"  element={<AttackChainsPage />} />
        <Route path="/system"         element={<SystemControl />} />
        <Route path="/traffic"        element={<TrafficExplorer />} />
        <Route path="/fuzzer/:id"     element={<Fuzzer />} />
        <Route path="/chains/:scanId" element={<ExploitChainViewer />} />
        <Route path="/chains"         element={<ExploitChainViewer />} />
        <Route path="/brain"          element={<BrainDashboard />} />
        <Route path="/intelligence"   element={<LiveIntelligence />} />
        <Route path="/swarm"          element={<SwarmIntelligence />} />
        <Route path="/evolution"      element={<SystemEvolution />} />
        <Route path="/orchestrator"   element={<OrchestratorPanel />} />
        <Route path="/mobile"         element={<Navigate to="/mobile-workspace" replace />} />
        <Route path="/mobile-agent"   element={<Navigate to="/mobile-workspace" replace />} />
        <Route path="/mobile-workspace" element={<MobileWorkspace />} />
        <Route path="/hunter"         element={<BountyHunter />} />
        <Route path="/secrets"        element={<SecretDashboard />} />

        {/* New pages */}
        <Route path="/god-mode"        element={<GodMode />} />
        <Route path="/research"        element={<Research />} />
        <Route path="/tools"           element={<Tools />} />
        <Route path="/ai-ops"          element={<AIModels />} />
        <Route path="/learning"        element={<Learning />} />
        <Route path="/simulation"      element={<Simulation />} />
        <Route path="/utilities"       element={<Utilities />} />
        <Route path="/reports"         element={<Reports />} />
        <Route path="/report-preview/:scanId" element={<ReportPreview />} />
        <Route path="/infrastructure"  element={<Infrastructure />} />
        <Route path="/mcp"             element={<MCPControl />} />
        <Route path="/ai-redteam"      element={<AIRedTeam />} />
        <Route path="/unified-scan"    element={<UnifiedScan />} />
        <Route path="/settings"        element={<Settings />} />
        <Route path="/queue-monitor"   element={<QueueMonitor />} />
        <Route path="/system-health"   element={<SystemHealth />} />
        <Route path="/payloads"         element={<PayloadLibrary />} />
        <Route path="/cicd"             element={<CICDCenter />} />
        <Route path="/web3"             element={<Web3Center />} />
        <Route path="/idor"             element={<IDORCenter />} />
        <Route path="/adaptive-planning" element={<AdaptivePlanning />} />
        <Route path="/tool-analytics"   element={<ToolAnalytics />} />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}
