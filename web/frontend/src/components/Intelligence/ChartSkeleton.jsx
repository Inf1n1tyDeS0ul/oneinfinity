import React from 'react'

export default function ChartSkeleton() {
  return (
    <div className="card col-span-1 sm:col-span-2 lg:col-span-2 animate-pulse">
      <div className="card-header border-b border-slate-800/50">
        <div className="h-4 w-48 bg-slate-800 rounded"></div>
      </div>
      <div className="p-4 h-64 flex items-end gap-2 px-8">
        {[...Array(10)].map((_, i) => (
          <div 
            key={i} 
            className="flex-1 bg-slate-800 rounded-t" 
            style={{ height: `${Math.floor(Math.random() * 60) + 20}%`, opacity: (10 - i) / 10 }}
          ></div>
        ))}
      </div>
    </div>
  )
}
