import React from 'react'
import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function RiskHeatmap({ data }) {
  if (!data || data.length === 0) return null;

  return (
    <div className="h-72 glass-card p-5">
      <h3 className="text-xs font-bold text-slate-400 mb-6 uppercase">Strategic Risk Heatmap</h3>
      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart margin={{ top: 10, right: 10, bottom: 20, left: 0 }}>
          <XAxis 
            type="number" 
            dataKey="probability" 
            name="Probability" 
            unit="%" 
            domain={[0, 100]} 
            tick={{fontSize: 10, fill: '#64748b'}} 
            label={{ value: 'Success Probability', position: 'insideBottom', offset: -10, fontSize: 10, fill: '#64748b' }}
          />
          <YAxis 
            type="number" 
            dataKey="impact" 
            name="Impact" 
            domain={[0, 10]} 
            tick={{fontSize: 10, fill: '#64748b'}} 
            label={{ value: 'Impact Score', angle: -90, position: 'insideLeft', fontSize: 10, fill: '#64748b' }}
          />
          <ZAxis type="number" dataKey="ev" range={[100, 500]} />
          <Tooltip 
            cursor={{ strokeDasharray: '3 3' }} 
            contentStyle={{background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', fontSize: '11px'}}
            itemStyle={{color: '#e2e8f0'}}
            formatter={(value, name) => [value, name]}
          />
          <Scatter name="Attack Paths" data={data}>
            {data.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.impact > 7 ? '#ef4444' : entry.impact > 4 ? '#f59e0b' : '#3b82f6'} 
                className="drop-shadow-[0_0_8px_rgba(0,0,0,0.5)]"
              />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  )
}
