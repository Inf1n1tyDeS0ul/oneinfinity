import React, { useState, useEffect, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { Search, LayoutDashboard, Target, ShieldAlert, Share2, Zap,
         Settings, Brain, Activity, Users, GitBranch,
         Smartphone, Trophy, Key, FlaskConical, Wrench, BarChart3,
         BookOpen, Network, Bot, Boxes, Telescope, TrendingUp,
         FileText, ServerCog, Flame } from 'lucide-react'
import clsx from 'clsx'

const ALL_ROUTES = [
  { path: '/dashboard',      label: 'Dashboard',        icon: LayoutDashboard, group: 'Operations' },
  { path: '/god-mode',       label: 'GOD MODE',         icon: Flame,           group: 'Operations' },
  { path: '/targets',        label: 'Targets',          icon: Target,          group: 'Operations' },
  { path: '/hunter',         label: 'Bounty Hunter',    icon: Trophy,          group: 'Operations' },
  { path: '/results',        label: 'Findings',         icon: ShieldAlert,     group: 'Analysis' },
  { path: '/attack-graph',   label: 'Attack Graph',     icon: Share2,          group: 'Analysis' },
  { path: '/chains',         label: 'Exploit Chains',   icon: Zap,             group: 'Analysis' },
  { path: '/traffic',        label: 'Traffic',          icon: Network,         group: 'Analysis' },
  { path: '/secrets',        label: 'Secrets',          icon: Key,             group: 'Analysis' },
  { path: '/intelligence',   label: 'Live Intel',       icon: Telescope,       group: 'Intelligence' },
  { path: '/research',       label: 'Research',         icon: FlaskConical,    group: 'Intelligence' },
  { path: '/simulation',     label: 'Simulation',       icon: TrendingUp,      group: 'Intelligence' },
  { path: '/learning',       label: 'Learning',         icon: BookOpen,        group: 'Intelligence' },
  { path: '/swarm',          label: 'Swarm',            icon: Users,           group: 'Agents & AI' },
  { path: '/brain',          label: 'Graph Brain',      icon: Brain,           group: 'Agents & AI' },
  { path: '/ai-ops',         label: 'AI Models',        icon: Bot,             group: 'Agents & AI' },
  { path: '/orchestrator',   label: 'Orchestrator',     icon: Boxes,           group: 'Agents & AI' },
  { path: '/mobile',         label: 'Mobile Security',  icon: Smartphone,      group: 'Platform' },
  { path: '/tools',          label: 'Tools & Plugins',  icon: Wrench,          group: 'Platform' },
  { path: '/reports',        label: 'Reports',          icon: FileText,        group: 'Platform' },
  { path: '/utilities',      label: 'Utilities',        icon: BarChart3,       group: 'Platform' },
  { path: '/evolution',      label: 'Evolution',        icon: GitBranch,       group: 'System' },
  { path: '/infrastructure', label: 'Infrastructure',   icon: ServerCog,       group: 'System' },
  { path: '/system',         label: 'System Control',   icon: Settings,        group: 'System' },
]

export function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const navigate = useNavigate()
  const inputRef = useRef(null)

  const filtered = query.trim()
    ? ALL_ROUTES.filter(r =>
        r.label.toLowerCase().includes(query.toLowerCase()) ||
        r.group.toLowerCase().includes(query.toLowerCase())
      )
    : ALL_ROUTES

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  useEffect(() => { setSelected(0) }, [query])

  const go = useCallback((path) => {
    navigate(path)
    onClose()
  }, [navigate, onClose])

  const handleKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, filtered.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
    if (e.key === 'Enter')     { e.preventDefault(); if (filtered[selected]) go(filtered[selected].path) }
    if (e.key === 'Escape')    { onClose() }
  }

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-xl bg-bg-secondary border border-bg-border rounded-2xl shadow-modal overflow-hidden animate-fade-in"
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-bg-border">
          <Search size={15} className="text-slate-500 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search pages..."
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-500 outline-none"
          />
          <kbd className="text-[10px] text-slate-600 bg-bg-elevated border border-bg-border rounded px-1.5 py-0.5 font-mono">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <p className="text-center text-xs text-slate-600 py-8">No results for "{query}"</p>
          ) : (
            filtered.map((route, i) => {
              const Icon = route.icon
              return (
                <button
                  key={route.path}
                  className={clsx(
                    'w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors duration-100',
                    i === selected ? 'bg-accent-primary/10 text-accent-primary' : 'text-slate-300 hover:bg-white/5'
                  )}
                  onClick={() => go(route.path)}
                  onMouseEnter={() => setSelected(i)}
                >
                  <Icon size={14} className="flex-shrink-0 opacity-70" />
                  <span className="flex-1 text-sm">{route.label}</span>
                  <span className="text-[10px] text-slate-600">{route.group}</span>
                </button>
              )
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 px-4 py-2 border-t border-bg-border text-[10px] text-slate-600">
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">↵</kbd> open</span>
          <span><kbd className="font-mono">esc</kbd> close</span>
        </div>
      </div>
    </div>,
    document.body
  )
}
