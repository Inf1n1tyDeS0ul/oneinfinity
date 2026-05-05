import React from 'react'

export default function StatCardSkeleton() {
  return (
    <div className="glass-card p-5 flex flex-col justify-between animate-pulse">
      <div className="flex justify-between items-start">
        <div className="h-3 w-24 bg-slate-800 rounded"></div>
        <div className="w-8 h-8 rounded-lg bg-slate-800"></div>
      </div>
      <div className="mt-4">
        <div className="h-8 w-16 bg-slate-800 rounded"></div>
      </div>
    </div>
  )
}
