import React from 'react'
import { useLocation, Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

const ROUTE_LABELS = {
  dashboard:      'Dashboard',
  targets:        'Targets',
  results:        'Findings',
  'attack-graph': 'Attack Graph',
  system:         'System Control',
  traffic:        'Traffic',
  chains:         'Exploit Chains',
  brain:          'Graph Brain',
  intelligence:   'Live Intel',
  swarm:          'Swarm',
  evolution:      'Evolution',
  orchestrator:   'Orchestrator',
  mobile:         'Mobile Security',
  hunter:         'Bounty Hunter',
  secrets:        'Secrets',
  'god-mode':     'GOD MODE',
  research:       'Research',
  tools:          'Tools & Plugins',
  'ai-ops':       'AI Models',
  learning:       'Learning',
  simulation:     'Simulation',
  utilities:      'Utilities',
  reports:        'Reports',
  infrastructure: 'Infrastructure',
}

export function Breadcrumbs() {
  const { pathname } = useLocation()

  // Hide on dashboard — no parent context
  if (pathname === '/dashboard' || pathname === '/') return null

  const segments = pathname.split('/').filter(Boolean)

  return (
    <nav className="flex items-center h-8 px-5 border-b border-bg-border gap-1.5 text-[11px] text-slate-500 flex-shrink-0">
      <Link to="/dashboard" className="hover:text-slate-300 transition-colors">
        Home
      </Link>
      {segments.map((seg, i) => {
        const path = '/' + segments.slice(0, i + 1).join('/')
        const label = ROUTE_LABELS[seg] || seg
        const isLast = i === segments.length - 1
        return (
          <React.Fragment key={path}>
            <ChevronRight size={10} className="text-slate-700" />
            {isLast ? (
              <span className="text-slate-300 font-medium">{label}</span>
            ) : (
              <Link to={path} className="hover:text-slate-300 transition-colors">
                {label}
              </Link>
            )}
          </React.Fragment>
        )
      })}
    </nav>
  )
}
