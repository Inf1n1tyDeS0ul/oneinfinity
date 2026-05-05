import React from 'react'

export default function StatCard({ label, value, icon: Icon, colorClass, className }) {
  const bgClass = colorClass ? colorClass.replace('text-', 'bg-') : 'bg-slate-500'
  
  return (
    <div className={`glass-card p-6 flex flex-col justify-between hover:border-slate-600 transition-all duration-300 group ${className}`}>
      <div className="flex justify-between items-start">
        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</span>
        <div className={`p-2.5 rounded-xl bg-opacity-10 group-hover:bg-opacity-20 transition-all ${bgClass}`}>
          <Icon size={18} className={`${colorClass} group-hover:scale-110 transition-transform`} />
        </div>
      </div>
      <div className="mt-4 flex items-baseline gap-1">
        <span className={`text-3xl font-bold tracking-tight ${colorClass}`}>{value}</span>
      </div>
    </div>
  )
}
