import React, { useEffect, useRef } from 'react'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const LEVEL_COLORS = {
  error:   'text-red-400',
  warn:    'text-yellow-400',
  success: 'text-emerald-400',
  info:    'text-slate-300',
}
const LEVEL_PREFIX = {
  error: '[-]', warn: '[!]', success: '[+]', info: '[*]',
}

export default function LogConsole() {
  const logs = useStore(s => s.logs)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  return (
    <div className="h-full overflow-y-auto bg-bg-primary px-3 py-1 font-mono text-xs">
      {logs.map((entry, i) => (
        <div key={i} className="flex gap-2 leading-5 hover:bg-white/3">
          <span className="text-slate-600 flex-shrink-0 select-none">
            {new Date(entry.timestamp).toLocaleTimeString()}
          </span>
          {entry.source && (
            <span className="text-accent-secondary/70 flex-shrink-0">[{entry.source}]</span>
          )}
          <span className={clsx(LEVEL_COLORS[entry.level] || 'text-slate-300')}>
            {LEVEL_PREFIX[entry.level] || '[*]'} {entry.message}
          </span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  )
}
