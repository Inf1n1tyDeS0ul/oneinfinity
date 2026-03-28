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
    <div className="h-full overflow-y-auto bg-bg-primary px-4 py-2 font-mono text-xs">
      {logs.length === 0 && (
        <div className="text-slate-600 py-2">// Waiting for log events...</div>
      )}
      {logs.map((entry, i) => (
        <div key={i} className="flex gap-2 leading-5.5 hover:bg-white/[0.02] rounded px-1 -mx-1">
          <span className="text-slate-700 flex-shrink-0 select-none tabular-nums">
            {new Date(entry.timestamp).toLocaleTimeString()}
          </span>
          {entry.source && (
            <span className="text-accent-secondary/60 flex-shrink-0">[{entry.source}]</span>
          )}
          <span className={clsx(LEVEL_COLORS[entry.level] || 'text-slate-400')}>
            <span className="opacity-60">{LEVEL_PREFIX[entry.level] || '[*]'}</span>{' '}
            {entry.message}
          </span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  )
}
