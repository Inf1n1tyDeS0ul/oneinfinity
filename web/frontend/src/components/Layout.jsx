import React, { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Share2, ShieldAlert, Target,
  Bell,
  ChevronLeft, ChevronRight, Play, Zap, Terminal,
  AlertTriangle, CheckCircle2, Info,
  Brain, Activity, Users, GitBranch, Cpu, Smartphone, Trophy, Key
} from 'lucide-react'
import { useStore } from '../store/useStore'
import ScanLauncher from './ScanLauncher'
import LogConsole from './LogConsole'
import clsx from 'clsx'

const NAV_ITEMS = [
  { path: '/dashboard',    label: 'Dashboard',    icon: LayoutDashboard },
  { path: '/targets',      label: 'Targets',      icon: Target },
  { path: '/results',      label: 'Results',      icon: ShieldAlert },
  { path: '/attack-graph', label: 'Attack Graph', icon: Share2 },
  { path: '/traffic',      label: 'Traffic',      icon: Terminal },
  { path: '/chains',       label: 'Chains',       icon: Zap },
  { path: '/system',       label: 'System',       icon: Terminal },
  { path: '/brain',        label: 'Brain',        icon: Brain },
  { path: '/intelligence', label: 'Intelligence', icon: Activity },
  { path: '/swarm',        label: 'Swarm',        icon: Users },
  { path: '/evolution',    label: 'Evolution',    icon: GitBranch },
  { path: '/orchestrator', label: 'Orchestrator', icon: Cpu },
  { path: '/mobile',       label: 'Mobile',       icon: Smartphone },
  { path: '/hunter',       label: 'Hunter',       icon: Trophy },
  { path: '/secrets',      label: 'Secrets',      icon: Key },
]

export default function Layout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [launcherOpen, setLauncherOpen] = useState(false)
  const [consoleOpen, setConsoleOpen] = useState(true)
  const { targets, selectedTarget, setSelectedTarget, notifications, stats } = useStore()
  const navigate = useNavigate()

  const activeScans = stats?.active_scans ?? 0

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* ── Top Nav ─────────────────────────────────────────────────── */}
      <header className="flex items-center gap-3 px-4 py-2 bg-bg-secondary border-b border-bg-border flex-shrink-0 z-20">
        {/* Logo */}
        <div className="flex items-center gap-2 mr-2 select-none">
          <Zap size={18} className="text-accent-primary" />
          <span className="font-bold text-accent-primary text-sm tracking-widest uppercase">One&Infinity</span>
        </div>

        {/* Target selector */}
        <div className="flex items-center gap-2">
          <span className="text-slate-500 text-xs">Target:</span>
          <select
            className="select w-56"
            value={selectedTarget || ''}
            onChange={e => setSelectedTarget(e.target.value || null)}
          >
            <option value="">— All Targets —</option>
            {targets.map(t => (
              <option key={t.id} value={t.domain}>{t.name} ({t.domain})</option>
            ))}
          </select>
        </div>

        {/* Launch scan button */}
        <button className="btn-primary flex items-center gap-1.5 ml-2" onClick={() => setLauncherOpen(true)}>
          <Play size={12} />
          Launch Scan
        </button>

        {/* Mode badge */}
        <div className="flex items-center gap-1.5 px-2 py-1 rounded border border-accent-secondary/30 bg-accent-secondary/10">
          <div className="w-1.5 h-1.5 rounded-full bg-accent-primary animate-pulse" />
          <span className="text-xs text-accent-secondary">Autonomous</span>
        </div>

        <div className="flex-1" />

        {/* Active scans */}
        {activeScans > 0 && (
          <div className="flex items-center gap-1.5 text-xs text-cyan-400">
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            {activeScans} scan{activeScans > 1 ? 's' : ''} running
          </div>
        )}

        {/* Notifications bell */}
        <button className="relative p-1.5 rounded hover:bg-white/5 transition-colors">
          <Bell size={15} className="text-slate-400" />
          {notifications.length > 0 && (
            <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-accent-danger text-[8px] flex items-center justify-center text-white">
              {notifications.length}
            </span>
          )}
        </button>
      </header>

      {/* ── Notification toasts ──────────────────────────────────────── */}
      <div className="fixed top-14 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {notifications.map(n => (
          <div key={n.id} className={clsx(
            'flex items-center gap-2 px-3 py-2 rounded border text-xs shadow-lg pointer-events-auto',
            n.type === 'error' ? 'bg-red-900/80 border-red-600/50 text-red-200' :
            n.type === 'success' ? 'bg-emerald-900/80 border-emerald-600/50 text-emerald-200' :
            'bg-bg-card border-bg-border text-slate-200'
          )}>
            {n.type === 'error' ? <AlertTriangle size={12} /> : n.type === 'success' ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Info size={12} className="text-cyan-400" />}
            {n.msg}
          </div>
        ))}
      </div>

      {/* ── Body ────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className={clsx(
          'flex flex-col bg-bg-secondary border-r border-bg-border flex-shrink-0 transition-all duration-200',
          sidebarOpen ? 'w-48' : 'w-12'
        )}>
          <nav className="flex-1 py-2 overflow-y-auto">
            {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
              <NavLink
                key={path}
                to={path}
                className={({ isActive }) => clsx(
                  'flex items-center gap-3 px-3 py-2 mx-1 rounded text-xs transition-all duration-150',
                  isActive
                    ? 'bg-accent-primary/15 text-accent-primary border-l-2 border-accent-primary'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                )}
                title={!sidebarOpen ? label : undefined}
              >
                <Icon size={14} className="flex-shrink-0" />
                {sidebarOpen && <span className="truncate">{label}</span>}
              </NavLink>
            ))}
          </nav>
          <button
            className="flex items-center justify-center p-2 border-t border-bg-border text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
          </button>
        </aside>

        {/* Main content + log console */}
        <div className="flex flex-col flex-1 overflow-hidden">
          <main className="flex-1 overflow-auto p-4">
            {children}
          </main>

          {/* Log Console (bottom) */}
          <div className={clsx(
            'flex-shrink-0 border-t border-bg-border transition-all duration-200',
            consoleOpen ? 'h-40' : 'h-8'
          )}>
            <div
              className="flex items-center gap-2 px-3 py-1.5 bg-bg-secondary cursor-pointer select-none border-b border-bg-border"
              onClick={() => setConsoleOpen(!consoleOpen)}
            >
              <Terminal size={12} className="text-accent-primary" />
              <span className="text-xs text-slate-400 flex-1">Console</span>
              <ChevronLeft size={12} className={clsx('text-slate-500 transition-transform', consoleOpen ? 'rotate-270' : 'rotate-90')} style={{ transform: consoleOpen ? 'rotate(-90deg)' : 'rotate(90deg)' }} />
            </div>
            {consoleOpen && <LogConsole />}
          </div>
        </div>
      </div>

      {/* Scan Launcher modal */}
      {launcherOpen && <ScanLauncher onClose={() => setLauncherOpen(false)} />}
    </div>
  )
}
