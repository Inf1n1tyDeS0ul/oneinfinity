import React, { useState } from 'react';
import { Search, Package, ArrowRight, Loader2 } from 'lucide-react';
import clsx from 'clsx';

const PackageList = ({ packages, onIngest }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [ingestingPkg, setIngestingPkg] = useState(null);

  const filteredPackages = (packages || []).filter(pkg => 
    pkg.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleIngest = async (name) => {
    setIngestingPkg(name);
    try {
      await onIngest(name);
    } finally {
      setIngestingPkg(null);
    }
  };

  return (
    <div className="glass-card flex flex-col h-[600px] animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 p-6 border-b border-white/5 bg-white/5">
        <div>
          <h2 className="text-xl font-black flex items-center gap-3 uppercase tracking-tighter">
            <Package className="w-6 h-6 text-primary" />
            Device Applications
          </h2>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">
            Browse and audit installed packages directly from the target hardware
          </p>
        </div>
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="FILTER PACKAGES..."
            className="w-full bg-black/40 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-xs font-mono focus:outline-none focus:border-primary/50 transition-colors uppercase"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto custom-scrollbar">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 z-10 bg-bg-primary/95 backdrop-blur-sm border-b border-white/5">
            <tr className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
              <th className="py-4 px-6">Package Identifier</th>
              <th className="py-4 px-6 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filteredPackages.length > 0 ? (
              filteredPackages.map((pkg, idx) => (
                <tr key={idx} className="hover:bg-white/5 transition-colors group">
                  <td className="py-4 px-6">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded bg-white/5 border border-white/5 flex items-center justify-center text-slate-500 group-hover:text-primary transition-colors">
                        <Package size={14} />
                      </div>
                      <span className="font-mono text-xs text-slate-300 group-hover:text-white transition-colors tracking-tight">
                        {pkg.name}
                      </span>
                    </div>
                  </td>
                  <td className="py-4 px-6 text-right">
                    <button
                      onClick={() => handleIngest(pkg.name)}
                      disabled={ingestingPkg !== null}
                      className={clsx(
                        "btn-primary py-1.5 px-4 text-[10px] font-black uppercase tracking-widest flex items-center gap-2 ml-auto transition-all active:scale-95",
                        ingestingPkg === pkg.name ? "opacity-100 bg-cyan-500 shadow-glow-cyan" : 
                        ingestingPkg ? "opacity-40 grayscale pointer-events-none" : "hover:shadow-glow-primary/20"
                      )}
                    >
                      {ingestingPkg === pkg.name ? (
                        <>
                          <Loader2 size={12} className="animate-spin" />
                          Pulling APK...
                        </>
                      ) : (
                        <>
                          Audit App
                          <ArrowRight size={12} />
                        </>
                      )}
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="2" className="py-20 text-center">
                  <div className="flex flex-col items-center opacity-30">
                    <Search size={40} className="mb-4" />
                    <p className="text-sm font-bold uppercase tracking-widest">
                      {searchTerm ? 'No matching packages' : 'No packages detected'}
                    </p>
                    <p className="text-[10px] mt-2">Check device connection or refresh list</p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      
      <div className="p-4 border-t border-white/5 bg-black/20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">
            {filteredPackages.length} Packages Indexed
          </span>
        </div>
        <div className="text-[9px] font-mono text-slate-600">
          DEVICE_SYNC_STATE: <span className="text-slate-400">READY</span>
        </div>
      </div>
    </div>
  );
};

export default PackageList;
