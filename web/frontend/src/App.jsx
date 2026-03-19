import React, { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Results from './pages/Results'
import AttackGraphPage from './pages/AttackGraph'
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
import MobileSecurity from './pages/MobileSecurity'
import BountyHunter from './pages/BountyHunter'
import SecretDashboard from './pages/SecretDashboard'

export default function App() {
  const { addLog, setStats, setTargets, setScans, setVulnerabilities } = useStore()

  // WebSocket for live logs
  useWebSocket((entry) => {
    if (entry.type === 'pong') return
    addLog(entry)
  })

  // Initial data load
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
    // Refresh stats and scans every 10s
    const interval = setInterval(() => {
      endpoints.stats().then(r => setStats(r.data)).catch(e => console.warn('Stats poll failed:', e.message))
      endpoints.scans().then(r => setScans(r.data)).catch(e => console.warn('Scans poll failed:', e.message))
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/results" element={<Results />} />
        <Route path="/attack-graph" element={<AttackGraphPage />} />
        <Route path="/system" element={<SystemControl />} />
        <Route path="/traffic" element={<TrafficExplorer />} />
        <Route path="/chains/:scanId" element={<ExploitChainViewer />} />
        <Route path="/chains" element={<ExploitChainViewer />} />
        <Route path="/brain" element={<BrainDashboard />} />
        <Route path="/intelligence" element={<LiveIntelligence />} />
        <Route path="/swarm" element={<SwarmIntelligence />} />
        <Route path="/evolution" element={<SystemEvolution />} />
        <Route path="/orchestrator" element={<OrchestratorPanel />} />
        <Route path="/mobile" element={<MobileSecurity />} />
        <Route path="/hunter" element={<BountyHunter />} />
        <Route path="/secrets" element={<SecretDashboard />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}
