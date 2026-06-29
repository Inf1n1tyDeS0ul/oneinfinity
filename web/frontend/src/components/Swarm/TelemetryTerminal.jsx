import React, { useEffect, useRef } from 'react'
import clsx from 'clsx'

/**
 * TelemetryTerminal Component
 * 
 * Styled log viewer with auto-scroll and ANSI-like color coding.
 */
export default function TelemetryTerminal({ logs = [] }) {
  const scrollRef = useRef(null)
  
  useEffect(() => {
     if (scrollRef.current) {
       scrollRef.current.scrollTop = scrollRef.current.scrollHeight
     }
  }, [logs])

  return (
    <div className="bg-black/80 rounded-xl border border-slate-800 p-4 h-52 font-mono text-[11px] overflow-y-auto custom-scrollbar shadow-inner" ref={scrollRef}>
      {logs.map((log, i) => {
        const isSuccess = log.includes('[+]')
        const isError = log.includes('[!]')
        const isInfo = log.includes('[*]')
        
        return (
          <div key={i} className={clsx(
            "mb-0.5",
            isSuccess ? "text-emerald-400" : 
            isError ? "text-red-400 font-bold" : 
            isInfo ? "text-cyan-400" : 
            "text-slate-500"
          )}>
            <span className="opacity-50 mr-2">{new Date().toLocaleTimeString().split(' ')[0]}</span>
            {log}
          </div>
        )
      })}
      {logs.length === 0 && (
        <div className="text-slate-600 italic">Awaiting telemetry data...</div>
      )}
      <div className="animate-pulse inline-block w-1.5 h-3 bg-emerald-500 ml-1 mt-1" />
    </div>
  )
}
