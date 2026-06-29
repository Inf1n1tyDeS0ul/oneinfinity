import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Terminal, Play, RefreshCw, AlertTriangle, Search, Database, Activity } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function Fuzzer() {
  const { id } = useParams()
  const { addNotification } = useStore()
  const [request, setRequest] = useState(null)
  const [fuzzParam, setFuzzParam] = useState('')
  const [results, setResults] = useState([])
  const [sortConfig, setSortConfig] = useState({ key: 'payload', direction: 'asc' })
  // Phase 2: fuzzer enhancements
  const [adaptiveRun, setAdaptiveRun] = useState(false)
  const [corpusStats, setCorpusStats] = useState(null)
  const [coverageEdges, setCoverageEdges] = useState(0)

  useEffect(() => {
    const fetchRequest = async () => {
      try {
        const res = await endpoints.getTrafficReq(id)
        const req = res.data
        setRequest(req)
        
        // Auto-select first parameter
        if (req.request_body) {
          try {
             const body = typeof req.request_body === 'string' ? JSON.parse(req.request_body) : req.request_body
             if (body && typeof body === 'object') {
               setFuzzParam(Object.keys(body)[0])
             }
          } catch (e) {
            // Not JSON
          }
        } else if (req.url && req.url.includes('?')) {
          const params = new URLSearchParams(req.url.split('?')[1])
          setFuzzParam(params.keys().next().value || '')
        }
      } catch (e) {
        addNotification(`Failed to load request: ${e.message}`, 'error')
      }
    }
    fetchRequest()
  }, [id])

  const handleStartFuzzing = async () => {
    setFuzzing(true)
    setResults([])
    try {
      const res = await endpoints.fuzzTraffic(id, {
        param: fuzzParam,
        values: null,
        adaptive_run: adaptiveRun,
        corpus_stats: corpusStats,
      })
      const data = res.data
      setResults(data?.results || data || [])
      // Update coverage edge count from response if provided
      if (data?.coverage_edges != null) setCoverageEdges(data.coverage_edges)
      if (data?.corpus_stats) setCorpusStats(data.corpus_stats)
      addNotification('Fuzzing completed', 'success')
    } catch (e) {
      addNotification(`Fuzzing failed: ${e.message}`, 'error')
    } finally {
      setFuzzing(false)
    }
  }

  const sortedResults = [...results].sort((a, b) => {
    let valA = a[sortConfig.key]
    let valB = b[sortConfig.key]
    
    if (valA === undefined || valA === null) valA = ''
    if (valB === undefined || valB === null) valB = ''

    if (typeof valA === 'string') valA = valA.toLowerCase()
    if (typeof valB === 'string') valB = valB.toLowerCase()

    if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1
    if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1
    return 0
  })

  const requestSort = (key) => {
    let direction = 'asc'
    if (sortConfig.key === key && sortConfig.direction === 'asc') direction = 'desc'
    setSortConfig({ key, direction })
  }

  return (
    <div className="flex flex-col gap-4 h-full">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Terminal size={14} className="text-accent-primary" />
        Fuzzer (Intruder)
      </h1>

      {request && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between gap-4">
            <div className="text-xs font-mono text-cyan-400 truncate flex-1">
              <span className="font-bold mr-2">{request.method}</span>
              {request.url}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <input 
                className="input text-xs w-48" 
                placeholder="Parameter to fuzz..." 
                value={fuzzParam}
                onChange={e => setFuzzParam(e.target.value)}
              />
              {/* Phase 2: adaptive run toggle */}
              <label className="flex items-center gap-1 text-xs text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={adaptiveRun}
                  onChange={e => setAdaptiveRun(e.target.checked)}
                  className="accent-cyan-500"
                />
                Adaptive Run
              </label>
              <button 
                className="btn-primary flex items-center gap-2 text-xs py-1.5" 
                onClick={handleStartFuzzing}
                disabled={fuzzing}
              >
                {fuzzing ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
                {fuzzing ? 'Fuzzing...' : 'Start Fuzzing'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase 2: Corpus Stats Panel */}
      <div className="card flex items-center gap-6 py-2 px-3 flex-wrap">
        <div className="flex items-center gap-1.5 text-xs text-slate-400">
          <Activity size={12} className="text-cyan-400" />
          <span>Coverage Edges:</span>
          <span className="font-mono text-cyan-300 font-semibold">{coverageEdges.toLocaleString()}</span>
        </div>
        {corpusStats ? (
          <>
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Database size={12} className="text-purple-400" />
              <span>Corpus Entries:</span>
              <span className="font-mono text-purple-300 font-semibold">{corpusStats.total_entries ?? '—'}</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <span>Seeds:</span>
              <span className="font-mono text-slate-300">{corpusStats.seed_count ?? '—'}</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <span>Last Mutation:</span>
              <span className="font-mono text-slate-300">{corpusStats.last_mutation ?? '—'}</span>
            </div>
          </>
        ) : (
          <span className="text-xs text-slate-600 italic">No corpus data yet — run a fuzz to populate.</span>
        )}
      </div>

      <div className="flex flex-1 gap-4 overflow-hidden min-h-0">
        {/* Results Table */}
        <div className="card flex-1 overflow-auto p-0 flex flex-col">
          <table className="w-full text-xs text-left border-collapse">
            <thead className="sticky top-0 bg-bg-secondary text-slate-500 border-b border-bg-border z-10">
              <tr>
                <th className="p-2 cursor-pointer hover:text-white select-none" onClick={() => requestSort('fuzz_value')}>Payload</th>
                <th className="p-2 cursor-pointer hover:text-white w-20 select-none" onClick={() => requestSort('status')}>Status</th>
                <th className="p-2 cursor-pointer hover:text-white w-20 select-none" onClick={() => requestSort('body_len')}>Length</th>
                <th className="p-2 cursor-pointer hover:text-white w-24 select-none" onClick={() => requestSort('duration_ms')}>Duration</th>
                <th className="p-2 select-none">Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {results.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 italic">
                    {fuzzing ? 'Fuzzing in progress...' : 'Select a parameter and start fuzzing to see results.'}
                  </td>
                </tr>
              ) : (
                sortedResults.map((res, i) => (
                  <tr 
                    key={`${res.fuzz_value}-${i}`} 
                    className={clsx(
                      'cursor-pointer transition-colors',
                      res.suspicious ? 'bg-red-900/10 hover:bg-red-900/20' : 'hover:bg-white/5',
                      selectedResult === res && 'bg-accent-primary/10'
                    )}
                    onClick={() => setSelectedResult(res)}
                  >
                    <td className="p-2 font-mono text-slate-300 truncate max-w-[200px]">{res.fuzz_value}</td>
                    <td className={clsx('p-2 font-mono', res.status >= 400 ? 'text-red-400' : 'text-green-400')}>{res.status}</td>
                    <td className="p-2 text-slate-400">{res.body_len}</td>
                    <td className="p-2 text-slate-400">{res.duration_ms}ms</td>
                    <td className="p-2">
                      <div className="flex items-center gap-1">
                        {res.suspicious && <AlertTriangle size={12} className="text-red-500" />}
                        <span className="text-[10px] text-slate-500 truncate">
                          {Array.isArray(res.flags) ? res.flags.join(', ') : ''}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Diff / Response View */}
        {selectedResult && (
          <div className="card w-1/3 flex flex-col gap-3 overflow-hidden bg-bg-secondary/50">
            <div className="flex items-center justify-between border-b border-bg-border pb-2">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Analysis</span>
              <button className="text-slate-500 hover:text-white px-2" onClick={() => setSelectedResult(null)}>×</button>
            </div>
            
            <div className="flex-1 overflow-auto space-y-4 pr-1">
              <div>
                <div className="text-[10px] font-bold text-slate-500 uppercase mb-1 flex items-center gap-2">
                   <div className="w-1 h-1 bg-cyan-400 rounded-full"></div> Payload Applied
                </div>
                <div className="bg-black/40 p-2 rounded font-mono text-xs text-cyan-400 break-all border border-cyan-900/30">
                  {selectedResult.fuzz_value}
                </div>
              </div>

              {selectedResult.diff && (
                <div>
                  <div className="text-[10px] font-bold text-slate-500 uppercase mb-1 flex items-center gap-2">
                    <div className="w-1 h-1 bg-yellow-400 rounded-full"></div> Response Diff
                  </div>
                  <pre className="text-[10px] text-slate-300 font-mono bg-black/40 rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap border border-bg-border">
                    {selectedResult.diff}
                  </pre>
                </div>
              )}

              <div className="flex flex-col h-full min-h-[300px]">
                <div className="text-[10px] font-bold text-slate-500 uppercase mb-1 flex items-center gap-2">
                   <div className="w-1 h-1 bg-slate-400 rounded-full"></div> Full Response
                </div>
                <pre className="flex-1 text-[10px] text-slate-300 font-mono bg-black/40 rounded p-2 overflow-auto whitespace-pre-wrap border border-bg-border">
                  {selectedResult.response_body}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
