import React from 'react'

export default function StatCard({ label, value, icon: Icon, colorClass, className }) {
  return (
    <div className={`glass-card p-5 flex flex-col justify-between hover:border-slate-700 transition-all ${className}`}>
      <div className="flex justify-between items-start">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{label}</span>
        <div className={`p-2 rounded-lg bg-opacity-10 ${colorClass.replace('text-', 'bg-')}`}>
          <Icon size={16} className={colorClass} />
        </div>
      </div>
      <div className="mt-4">
        <span className={`text-3xl font-bold ${colorClass}`}>{value}</span>
      </div>
    </div>
  )
}
