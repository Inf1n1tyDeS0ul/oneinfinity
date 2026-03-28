import React, { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Share2, ShieldAlert, Target,
  Bell, ChevronLeft, ChevronRight, Play, Zap, Terminal,
  AlertTriangle, CheckCircle2, Info, Brain, Activity,
  Users, GitBranch, Smartphone, Trophy, Key,
  Search, FlaskConical, Wrench, BarChart3,
  BookOpen, Network, Settings, Bot, Boxes,
  X, Telescope, TrendingUp, FileText, ServerCog,
  Flame, Sun, Moon, Menu
} from 'lucide-react'
import { useStore } from '../store/useStore'
import { useTheme } from '../hooks/useTheme'
import { useLocalStorage } from '../hooks/useLocalStorage'
import { CommandPalette } from './ui/CommandPalette'
import { Breadcrumbs } from './ui/Breadcrumbs'
import ScanLauncher from './ScanLauncher'
import LogConsole from './LogConsole'
import clsx from 'clsx'

const NAV_GROUPS = [
  {
    label: 'Operations',
    items: [
      { path: '/dashboard',    label: 'Dashboard',      icon: LayoutDashboard },
      { path: '/god-mode',     label: 'GOD MODE',       icon: Flame, accent: true },
      { path: '/targets',      label: 'Targets',        icon: Target },
      { path: '/hunter',       label: 'Bounty Hunter',  icon: Trophy },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { path: '/results',      label: 'Findings',       icon: ShieldAlert },
      { path: '/attack-graph', label: 'Attack Graph',   icon: Share2 },
      { path: '/chains',       label: 'Exploit Chains', icon: Zap },
      { path: '/traffic',      label: 'Traffic',        icon: Network },
      { path: '/secrets',      label: 'Secrets',        icon: Key },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { path: '/intelligence', label: 'Live Intel',     icon: Telescope },
      { path: '/research',     label: 'Research',       icon: FlaskConical },
      { path: '/simulation',   label: 'Simulation',     icon: TrendingUp },
      { path: '/learning',     label: 'Learning',       icon: BookOpen },
    ],
  },
  {
    label: 'Agents & AI',
    items: [
      { path: '/swarm',        label: 'Swarm',          icon: Users },
      { path: '/brain',        label: 'Graph Brain',    icon: Brain },
      { path: '/ai-ops',       label: 'AI Models',      icon: Bot },
      { path: '/orchestrator', label: 'Orchestrator',   icon: Boxes },
    ],
  },
  {
    label: 'Platform',
    items: [
      { path: '/mobile',       label: 'Mobile Security', icon: Smartphone },
      { path: '/tools',        label: 'Tools & Plugins', icon: Wrench },
      { path: '/reports',      label: 'Reports',        icon: FileText },
      { path: '/utilities',    label: 'Utilities',      icon: BarChart3 },
    ],
  },
  {
    label: 'System',
    items: [
      { path: '/evolution',    label: 'Evolution',      icon: GitBranch },
      { path: '/infrastructure', label: 'Infrastructure', icon: ServerCog },
      { path: '/system',       label: 'System Control', icon: Settings },
    ],
  },
]

export default function Layout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useLocalStorage('sidebar-open', true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [launcherOpen, setLauncherOpen] = useState(false)
  const [consoleOpen, setConsoleOpen] = useLocalStorage('console-open', false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { targets, selectedTarget, setSelectedTarget, notifications, stats, apiOffline } = useStore()
  const { theme, toggleTheme } = useTheme()
  const location = useLocation()

  const activeScans = stats?.active_scans ?? 0

  // Global Cmd+K listener
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setPaletteOpen(p => !p)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Close mobile drawer on route change
  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  const NavItems = ({ collapsed }) => (
    <>
      {NAV_GROUPS.map(group => (
        <div key={group.label}>
          {!collapsed && (
            <div className="nav-group-label">{group.label}</div>
          )}
          {collapsed && group.label !== 'Operations' && (
            <div className="mx-3 my-1.5 border-t border-bg-border opacity-50" />
          )}
          {group.items.map(({ path, label, icon: Icon, accent }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) => isActive
                ? 'nav-item-active'
                : accent
                ? 'nav-item flex items-center gap-2.5 px-3 py-2 mx-2 rounded-lg text-sm transition-all duration-150 cursor-pointer select-none text-orange-400 hover:text-orange-300 hover:bg-orange-500/10'
                : 'nav-item-inactive'
              }
              title={collapsed ? label : undefined}
            >
              <Icon size={15} className={clsx('flex-shrink-0', accent && 'drop-shadow-[0_0_4px_rgba(251,146,60,0.8)]')} />
              {!collapsed && <span className={clsx('truncate text-sm', accent && 'font-semibold tracking-wide')}>{label}</span>}
            </NavLink>
          ))}
        </div>
      ))}
    </>
  )

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-bg-primary">
      {/* ── Top Header ─────────────────────────────────────────── */}
      <header className="flex items-center gap-3 px-4 h-12 bg-bg-secondary border-b border-bg-border flex-shrink-0 z-20">
        {/* Mobile hamburger */}
        <button
          className="btn-icon md:hidden"
          onClick={() => setMobileOpen(true)}
          aria-label="Open menu"
        >
          <Menu size={16} />
        </button>

        {/* Logo */}
        <div className="flex items-center gap-2 mr-2 select-none">
          <Zap size={16} className="text-accent-primary" style={{ filter: 'drop-shadow(0 0 6px rgba(0,217,255,0.8))' }} />
          <span className="font-bold text-accent-primary text-sm tracking-[0.2em] uppercase font-mono">
            One<span className="text-accent-secondary">&amp;</span>Infinity
          </span>
        </div>

        <div className="w-px h-5 bg-bg-border mx-1 hidden md:block" />

        {/* Target selector */}
        <div className="hidden md:flex items-center gap-2">
          <span className="text-xs text-slate-500 font-medium">Target</span>
          <select
            className="bg-bg-elevated border border-bg-border rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-accent-primary/50 w-52 cursor-pointer transition-colors"
            value={selectedTarget || ''}
            onChange={e => setSelectedTarget(e.target.value || null)}
          >
            <option value="">— All Targets —</option>
            {targets.map(t => (
              <option key={t.id} value={t.domain}>{t.name} ({t.domain})</option>
            ))}
          </select>
        </div>

        {/* Launch Scan */}
        <button className="btn-primary btn-sm ml-1 h-7" onClick={() => setLauncherOpen(true)}>
          <Play size={10} />
          <span className="hidden sm:inline">Launch Scan</span>
        </button>

        {/* Cmd+K search trigger */}
        <button
          className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-bg-elevated border border-bg-border text-xs text-slate-500 hover:text-slate-300 hover:border-slate-600 transition-colors cursor-pointer"
          onClick={() => setPaletteOpen(true)}
          aria-label="Open command palette"
        >
          <Search size={11} />
          <span>Search</span>
          <kbd className="text-[10px] bg-bg-primary border border-bg-border rounded px-1 font-mono">⌘K</kbd>
        </button>

        {/* Autonomous badge */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-accent-primary/20 bg-accent-primary/5">
          <span className="status-dot-pulse" />
          <span className="text-xs text-accent-primary font-medium">Autonomous</span>
        </div>

        <div className="flex-1" />

        {/* Active scans */}
        {activeScans > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
            <Activity size={11} className="text-cyan-400 animate-pulse" />
            <span className="text-xs text-cyan-400 font-medium">{activeScans} scanning</span>
          </div>
        )}

        {/* Stats */}
        <div className="hidden lg:flex items-center gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1">
            <ShieldAlert size={11} className="text-red-400" />
            <span className="text-slate-300 font-medium">{stats?.total_vulnerabilities ?? 0}</span> vulns
          </span>
          <span className="flex items-center gap-1">
            <Target size={11} className="text-accent-secondary" />
            <span className="text-slate-300 font-medium">{stats?.total_targets ?? 0}</span> targets
          </span>
        </div>

        {/* Theme toggle */}
        <button
          className="btn-icon"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        {/* Notifications */}
        <button className="btn-icon relative" aria-label="Notifications">
          <Bell size={14} />
          {notifications.length > 0 && (
            <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-accent-danger" />
          )}
        </button>

        {/* Console toggle */}
        <button
          className="btn-icon"
          onClick={() => setConsoleOpen(!consoleOpen)}
          title="Toggle console"
          aria-label="Toggle console"
        >
          <Terminal size={14} className={consoleOpen ? 'text-accent-primary' : ''} />
        </button>
      </header>

      {/* ── Notification toasts ─────────────────────────────────── */}
      <div className="fixed top-14 right-4 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full">
        {notifications.map(n => (
          <div key={n.id} className={clsx(
            'toast pointer-events-auto',
            n.type === 'error' ? 'toast-error' :
            n.type === 'success' ? 'toast-success' :
            n.type === 'warn' ? 'toast-warn' : 'toast-info'
          )}>
            {n.type === 'error'   ? <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" /> :
             n.type === 'success' ? <CheckCircle2  size={14} className="flex-shrink-0 mt-0.5 text-emerald-400" /> :
                                    <Info          size={14} className="flex-shrink-0 mt-0.5 text-cyan-400" />}
            <span className="text-sm leading-relaxed">{n.msg}</span>
          </div>
        ))}
      </div>

      {/* ── Body ────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Mobile drawer */}
        {mobileOpen && (
          <div className="fixed inset-0 z-40 md:hidden">
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
            <aside className="relative flex flex-col w-64 h-full bg-bg-secondary border-r border-bg-border">
              <div className="flex items-center justify-between px-4 h-12 border-b border-bg-border flex-shrink-0">
                <span className="font-bold text-accent-primary text-sm tracking-[0.2em] uppercase font-mono">
                  One<span className="text-accent-secondary">&amp;</span>Infinity
                </span>
                <button className="btn-icon" onClick={() => setMobileOpen(false)} aria-label="Close menu">
                  <X size={14} />
                </button>
              </div>
              <nav className="flex-1 py-2 overflow-y-auto overflow-x-hidden">
                <NavItems collapsed={false} />
              </nav>
            </aside>
          </div>
        )}

        {/* Desktop sidebar */}
        <aside className={clsx(
          'hidden md:flex flex-col bg-bg-secondary border-r border-bg-border flex-shrink-0 transition-all duration-200',
          sidebarOpen ? 'w-52' : 'w-14'
        )}>
          <nav className="flex-1 py-2 overflow-y-auto overflow-x-hidden">
            <NavItems collapsed={!sidebarOpen} />
          </nav>
          <button
            className="flex items-center justify-center h-10 border-t border-bg-border text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
          </button>
        </aside>

        {/* Main content */}
        <div className="flex flex-col flex-1 overflow-hidden">
          <Breadcrumbs />
          <main className="flex-1 overflow-auto p-5 animate-fade-in">
            {children}
          </main>

          {/* Log Console */}
          {consoleOpen && (
            <div className="flex-shrink-0 border-t border-bg-border h-44">
              <div className="flex items-center gap-2 px-4 py-2 bg-bg-secondary border-b border-bg-border">
                <Terminal size={12} className="text-accent-primary" />
                <span className="text-xs font-medium text-slate-400 flex-1 font-mono">Console</span>
                <button className="btn-icon" onClick={() => setConsoleOpen(false)} aria-label="Close console">
                  <X size={12} />
                </button>
              </div>
              <LogConsole />
            </div>
          )}
        </div>
      </div>

      {/* ── Status bar ──────────────────────────────────────────── */}
      <div className="h-6 bg-bg-secondary border-t border-bg-border flex items-center px-4 gap-4 text-[10px] text-slate-600 flex-shrink-0">
        <span className="flex items-center gap-1">
          {apiOffline ? (
            <>
              <span className="status-dot-error" style={{ width: '6px', height: '6px' }} />
              <span className="text-red-400">API Offline</span>
            </>
          ) : (
            <>
              <span className="status-dot-online" style={{ width: '6px', height: '6px' }} />
              <span className="text-slate-500">API Connected</span>
            </>
          )}
        </span>
        <span className="text-slate-700">|</span>
        <span>Neo4j: <span className="text-slate-500">{stats?.neo4j_connected ? 'Connected' : 'Offline'}</span></span>
        <span className="text-slate-700">|</span>
        <span>Findings: <span className="text-slate-400 font-medium">{stats?.total_vulnerabilities ?? 0}</span></span>
        <span className="text-slate-700">|</span>
        <span>Targets: <span className="text-slate-400 font-medium">{stats?.total_targets ?? 0}</span></span>
        <div className="flex-1" />
        <span className="font-mono">One&amp;Infinity v2.0</span>
      </div>

      {/* Command Palette */}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />

      {/* Scan Launcher modal */}
      {launcherOpen && <ScanLauncher onClose={() => setLauncherOpen(false)} />}
    </div>
  )
}
