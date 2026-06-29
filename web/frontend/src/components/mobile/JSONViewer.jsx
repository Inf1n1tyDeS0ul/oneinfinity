import React, { useState } from 'react';
import { ChevronRight, ChevronDown, Copy } from 'lucide-react';
import clsx from 'clsx';

export default function JSONViewer({ data, level = 0 }) {
  const [isExpanded, setIsExpanded] = useState(true);

  if (data === null) return <span className="text-slate-500 italic">null</span>;
  if (data === undefined) return <span className="text-slate-500 italic">undefined</span>;

  const type = typeof data;

  if (type === 'string') return <span className="text-emerald-400">"{data}"</span>;
  if (type === 'number') return <span className="text-orange-400">{data}</span>;
  if (type === 'boolean') return <span className="text-purple-400">{data.toString()}</span>;

  const isArray = Array.isArray(data);
  const keys = Object.keys(data);

  if (keys.length === 0) return <span>{isArray ? '[]' : '{}'}</span>;

  return (
    <div className={clsx("font-mono text-[11px]", level > 0 && "ml-4")}>
      <div 
        className="flex items-center gap-1 cursor-pointer hover:bg-white/5 rounded px-1 -ml-1 group"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        {isExpanded ? <ChevronDown size={10} className="text-slate-500" /> : <ChevronRight size={10} className="text-slate-500" />}
        <span className="text-slate-400">{isArray ? '[' : '{'}</span>
        {!isExpanded && <span className="text-slate-500 text-[9px]">... {keys.length} items</span>}
        {!isExpanded && <span className="text-slate-400">{isArray ? ']' : '}'}</span>}
      </div>

      {isExpanded && (
        <div className="border-l border-white/5 ml-1 pl-2 my-1">
          {keys.map((key, i) => (
            <div key={key} className="flex flex-wrap">
              {!isArray && <span className="text-cyan-400 mr-1">"{key}":</span>}
              <JSONViewer data={data[key]} level={level + 1} />
              {i < keys.length - 1 && <span className="text-slate-500">,</span>}
            </div>
          ))}
        </div>
      )}

      {isExpanded && <div className="text-slate-400">{isArray ? ']' : '}'}</div>}
    </div>
  );
}
