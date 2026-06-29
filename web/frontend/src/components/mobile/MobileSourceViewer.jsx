import React, { useState, useEffect } from 'react';
import { FileCode, Search, Terminal, Zap, ChevronRight, Code } from 'lucide-react';
import api from '../../utils/api';
import clsx from 'clsx';

export default function MobileSourceViewer({ appId, initialFile, onHookRequest }) {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(initialFile || null);
  const [content, setContent] = useState('');

  useEffect(() => {
    if (initialFile) setSelectedFile(initialFile);
  }, [initialFile]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    if (!appId) return;
    api.get(`/mobile/apps/${appId}/files`).then(r => setFiles(r.data.files || [])).catch(() => {});
  }, [appId]);

  useEffect(() => {
    if (selectedFile) {
      setLoading(true);
      api.get(`/mobile/apps/${appId}/source`, { params: { file_path: selectedFile } })
        .then(r => setContent(r.data.content))
        .catch(() => setContent('// Failed to load source content'))
        .finally(() => setLoading(false));
    }
  }, [appId, selectedFile]);

  const filteredFiles = files.filter(f => f.toLowerCase().includes(filter.toLowerCase())).slice(0, 50);

  return (
    <div className="flex h-full glass-card overflow-hidden bg-bg-secondary/20">
      {/* File Browser */}
      <div className="w-64 border-r border-bg-border flex flex-col shrink-0 bg-black/20">
        <div className="p-3 border-b border-bg-border">
          <div className="relative">
            <Search size={10} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input 
              className="w-full bg-black/40 border border-bg-border rounded-lg pl-8 pr-3 py-1.5 text-[10px] font-bold text-slate-300 outline-none focus:border-accent-primary/50"
              placeholder="Filter files..."
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-0.5 scrollbar-none">
          {filteredFiles.map(f => (
            <div 
              key={f}
              onClick={() => setSelectedFile(f)}
              className={clsx(
                "px-2 py-1.5 rounded-lg text-[9px] font-mono cursor-pointer transition-all truncate",
                selectedFile === f ? "bg-accent-primary/10 text-accent-primary border border-accent-primary/20" : "text-slate-500 hover:text-slate-300 hover:bg-white/5"
              )}
            >
              {f.split('/').pop()}
              <div className="text-[7px] opacity-40 truncate">{f.split('/').slice(0, -1).join('/')}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Code Viewer */}
      <div className="flex-1 flex flex-col overflow-hidden bg-black/40">
        {selectedFile ? (
          <>
            <div className="h-10 border-b border-bg-border flex items-center justify-between px-4 bg-bg-secondary/40">
              <div className="flex items-center gap-2">
                <FileCode size={14} className="text-accent-primary" />
                <span className="text-[10px] font-bold text-slate-400 font-mono">{selectedFile}</span>
              </div>
              <button 
                onClick={() => onHookRequest?.(selectedFile)}
                className="flex items-center gap-1.5 px-3 py-1 bg-accent-primary/10 border border-accent-primary/20 rounded-md text-[9px] font-black text-accent-primary uppercase hover:bg-accent-primary hover:text-black transition-all"
              >
                <Terminal size={10} /> Hook Class
              </button>
            </div>
            <div className="flex-1 overflow-auto p-6 font-mono text-[11px] leading-relaxed scrollbar-thin">
              {loading ? (
                <div className="h-full flex items-center justify-center">
                  <RefreshCw size={24} className="animate-spin text-slate-700" />
                </div>
              ) : (
                <pre className="text-emerald-400/90 whitespace-pre">
                  {content.split('\n').map((line, i) => (
                    <div key={i} className="group flex gap-4 hover:bg-white/5 -mx-6 px-6">
                      <span className="w-8 shrink-0 text-slate-700 text-right select-none">{i + 1}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </pre>
              )}
            </div>
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center opacity-20 space-y-4">
            <Code size={48} />
            <p className="text-sm font-black uppercase tracking-widest">Select source file to inspect</p>
          </div>
        )}
      </div>
    </div>
  );
}
