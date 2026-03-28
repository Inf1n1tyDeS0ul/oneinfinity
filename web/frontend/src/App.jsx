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
import { ThemeProvider } from './context/ThemeContext'
import { ErrorBoundary } from './components/ui/ErrorBoundary'

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
    <ThemeProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"      element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
          <Route path="/targets"        element={<ErrorBoundary><Targets /></ErrorBoundary>} />
          <Route path="/results"        element={<ErrorBoundary><Results /></ErrorBoundary>} />
          <Route path="/attack-graph"   element={<ErrorBoundary><AttackGraphPage /></ErrorBoundary>} />
          <Route path="/system"         element={<ErrorBoundary><SystemControl /></ErrorBoundary>} />
          <Route path="/traffic"        element={<ErrorBoundary><TrafficExplorer /></ErrorBoundary>} />
          <Route path="/chains/:scanId" element={<ErrorBoundary><ExploitChainViewer /></ErrorBoundary>} />
          <Route path="/chains"         element={<ErrorBoundary><ExploitChainViewer /></ErrorBoundary>} />
          <Route path="/brain"          element={<ErrorBoundary><BrainDashboard /></ErrorBoundary>} />
          <Route path="/intelligence"   element={<ErrorBoundary><LiveIntelligence /></ErrorBoundary>} />
          <Route path="/swarm"          element={<ErrorBoundary><SwarmIntelligence /></ErrorBoundary>} />
          <Route path="/evolution"      element={<ErrorBoundary><SystemEvolution /></ErrorBoundary>} />
          <Route path="/orchestrator"   element={<ErrorBoundary><OrchestratorPanel /></ErrorBoundary>} />
          <Route path="/mobile"         element={<ErrorBoundary><MobileSecurity /></ErrorBoundary>} />
          <Route path="/hunter"         element={<ErrorBoundary><BountyHunter /></ErrorBoundary>} />
          <Route path="/secrets"        element={<ErrorBoundary><SecretDashboard /></ErrorBoundary>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Layout>
    </ThemeProvider>
  )
}
