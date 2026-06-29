import React, { useState, useEffect, useRef } from 'react'
import { Smartphone, Upload, Shield, Zap, RefreshCw, Layers, History, Activity } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'
import MobileXRayHUD from '../components/mobile/MobileXRayHUD'
import MobileReportViewer from '../components/mobile/MobileReportViewer'
import PackageList from '../components/mobile/PackageList'

export default function MobileSecurity() {
  const { addNotification } = useStore()
  const [file, setFile] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [appId, setAppId] = useState(null)
  const [report, setReport] = useState(null)
  const [activePhase, setActivePhase] = useState('idle')
  const [progress, setProgress] = useState(0)
  const [uploadPct, setUploadPct] = useState(0)
  const [history, setHistory] = useState([])
  const [useMobsf, setUseMobsf] = useState(false)
  const [mobsfAvailable, setMobsfAvailable] = useState(null)  // null=checking, true/false
  const [devices, setDevices] = useState([])
  const [selectedDevice, setSelectedDevice] = useState('')
  const [runDynamic, setRunDynamic] = useState(false)
  const [packages, setPackages] = useState([])
  const [loadingPackages, setLoadingPackages] = useState(false)
  const pollRef = useRef(null)

  const loadHistory = async () => {
    try {
      const r = await endpoints.mobileApps()
      setHistory(Array.isArray(r.data) ? r.data : (r.data?.apps || []))
    } catch (e) { console.error(e) }
  }

  const loadDevices = async () => {
    try {
      const r = await endpoints.mobileDevices()
      const devList = Array.isArray(r.data) ? r.data : (r.data?.devices || [])
      setDevices(devList)
      if (devList.length > 0 && !selectedDevice) {
        setSelectedDevice(devList[0].serial)
      }
    } catch (e) {
      console.error(e)
      setDevices([])
      addNotification('Failed to fetch mobile devices', 'error')
    }
  }

  const loadPackages = async (serial) => {
    if (!serial) {
      setPackages([])
      return
    }
    setLoadingPackages(true)
    try {
      const r = await endpoints.devicePackages(serial)
      setPackages(r.data || [])
    } catch (e) {
      console.error(e)
      addNotification('Failed to fetch device packages', 'error')
    } finally {
      setLoadingPackages(false)
    }
  }

  const checkMobsf = async () => {
    try {
      const r = await endpoints.mobileMobsfStatus()
      setMobsfAvailable(r.data.available)
      if (!r.data.available) setUseMobsf(false)
    } catch { setMobsfAvailable(false) }
  }

  useEffect(() => { loadHistory(); checkMobsf(); loadDevices() }, [])

  // Auto-poll ADB devices every 5s so newly connected devices appear automatically
  useEffect(() => {
    const id = setInterval(loadDevices, 5000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    if (selectedDevice) {
      loadPackages(selectedDevice)
    }
  }, [selectedDevice])

  const startAnalysisPoll = (id) => {
    if (pollRef.current) clearInterval(pollRef.current)
    
    pollRef.current = setInterval(async () => {
      try {
        // Poll scan status for accurate progress
        const scanRes = await endpoints.scans().catch(() => null)
        const scans = scanRes?.data || []
        const scanEntry = (Array.isArray(scans) ? scans : []).find(s => s.scan_id === `mobile_${id}`)
        
        if (scanEntry) {
          const pct = scanEntry.progress || 0
          const phase = scanEntry.current_phase || 'scanning'
          if (pct > 0) {
            setProgress(pct)
            setActivePhase(phase)
          }
          if (scanEntry.status === 'completed' || scanEntry.status === 'failed') {
            const r = await endpoints.mobileFullReport(id)
            const data = r.data || {}
            setProgress(100)
            setActivePhase('completed')
            setReport(data)
            clearInterval(pollRef.current)
            setAnalyzing(false)
            addNotification(scanEntry.status === 'completed' ? 'Mobile analysis complete' : 'Analysis failed', scanEntry.status === 'completed' ? 'success' : 'error')
            loadHistory()
            return
          }
        }

        // Fallback: infer from report content
        const r = await endpoints.mobileFullReport(id)
        const data = r.data || {}
        if (data.static_analysis && (scanEntry?.progress || 0) < 50) {
           setActivePhase('ai')
           setProgress(prev => Math.max(prev, 55))
        }
        if (data.ai_reverse_engineering && (scanEntry?.progress || 0) < 75) {
           setActivePhase('secrets')
           setProgress(prev => Math.max(prev, 80))
        }
        if (data.all_vulnerabilities || data.risk_score !== undefined) {
          setActivePhase('network')
          setProgress(100)
          setReport(data)
          clearInterval(pollRef.current)
          setAnalyzing(false)
          addNotification('Mobile analysis complete', 'success')
          loadHistory()
        }
      } catch (err) {
        console.error('Report poll failed', err)
      }
    }, 5000)
  }

  const handleUpload = async (e) => {
    e.preventDefault()
    if (!file) return addNotification('Select an APK/IPA file first', 'error')
    setAnalyzing(true)
    setReport(null)
    setUploadPct(0)
    setActivePhase('binary')
    setProgress(5)

    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await endpoints.mobileUpload(formData, (evt) => {
        if (evt.total) {
          const pct = Math.round((evt.loaded / evt.total) * 100)
          setUploadPct(pct)
          setProgress(Math.min(20, Math.floor(pct / 5)))
        }
      })
      setUploadPct(100)
      const id = res.data.app_id
      setAppId(id)
      
      await endpoints.mobileAnalyze(id, {
        run_dynamic: runDynamic,
        device_id: selectedDevice,
        run_api_attack: true,
        run_mobsf: useMobsf,
      })

      setActivePhase('static')
      setProgress(30)
      startAnalysisPoll(id)
    } catch (err) {
      addNotification(`Upload failed: ${err.message}`, 'error')
      setAnalyzing(false)
      setActivePhase('idle')
      setProgress(0)
    }
  }

  const handlePackageIngest = async (pkgName) => {
    if (!selectedDevice) return addNotification('No device selected', 'error')
    setAnalyzing(true)
    setReport(null)
    setUploadPct(100)
    setActivePhase('binary')
    setProgress(10)

    try {
      addNotification(`Ingesting package: ${pkgName}`, 'info')
      const res = await endpoints.packageIngest(selectedDevice, pkgName)
      const id = res.data.app_id
      setAppId(id)
      
      await endpoints.mobileAnalyze(id, {
        run_dynamic: true, 
        device_id: selectedDevice,
        run_api_attack: true,
        run_mobsf: useMobsf,
      })

      setActivePhase('static')
      setProgress(30)
      startAnalysisPoll(id)
    } catch (err) {
      addNotification(`Ingest failed: ${err.message}`, 'error')
      setAnalyzing(false)
      setActivePhase('idle')
      setProgress(0)
    }
  }

  const selectFromHistory = async (app) => {
    setAnalyzing(true)
    setReport(null)
    setAppId(app.id)
    try {
      const r = await endpoints.mobileFullReport(app.id)
      setReport(r.data)
    } catch (e) { addNotification('Failed to load archived report', 'error') }
    finally { setAnalyzing(false) }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 px-2">
        <div className="flex items-center gap-4">
           <div className="p-2.5 rounded-xl bg-accent-primary/10 border border-accent-primary/20 shadow-glow-cyan/5">
              <Smartphone size={20} className="text-accent-primary" />
           </div>
           <div>
              <h1 className="text-xl font-black text-slate-100 tracking-tighter uppercase">Mobile Forensic Lab</h1>
              <div className="flex items-center gap-2 mt-1">
                <span className="flex items-center gap-1.5 text-[9px] font-bold text-emerald-400 uppercase tracking-widest">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Decompilation Core Active
                </span>
                <span className="text-[9px] text-slate-600 font-mono font-medium">STATION: MOBILE_ALPHA_01</span>
              </div>
           </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1 flex flex-col gap-4">
          <section className="glass-card p-5">
            <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Upload size={12} className="text-accent-primary" /> Deploy Artifact
            </h3>
            <form onSubmit={handleUpload} className="space-y-4">
              <div className="group border-2 border-dashed border-bg-border rounded-2xl p-6 text-center hover:border-accent-primary/50 transition-all cursor-pointer relative bg-bg-primary/20 overflow-hidden">
                <input
                  type="file"
                  onChange={e => setFile(e.target.files[0])}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                />
                <div className="relative z-0">
                  <div className="w-10 h-10 rounded-full bg-bg-elevated flex items-center justify-center mx-auto mb-3 group-hover:scale-110 transition-transform">
                    <Upload size={18} className="text-slate-500 group-hover:text-accent-primary" />
                  </div>
                  <div className="text-[11px] font-bold text-slate-400 group-hover:text-slate-200">
                    {file ? <span className="text-accent-primary font-mono truncate block max-w-[120px] mx-auto">{file.name}</span> : 'BROWSE BINARY'}
                  </div>
                  <div className="text-[9px] text-slate-600 mt-1 uppercase font-black">APK / IPA / AAB</div>
                </div>
              </div>

              {/* Device Selector */}
              <div className="flex flex-col gap-2">
                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                  <Smartphone size={12} className="text-accent-primary" /> Target Device
                </label>
                <div className="relative">
                  <select
                    className="bg-bg-primary/40 border border-bg-border rounded-xl p-2.5 text-[11px] font-bold text-slate-200 outline-none focus:border-accent-primary/50 transition-all w-full appearance-none"
                    value={selectedDevice}
                    onChange={e => setSelectedDevice(e.target.value)}
                    disabled={analyzing}
                  >
                    <option value="">No Device Selected</option>
                    {devices.map(d => (
                      <option key={d.serial} value={d.serial}>
                        {d.serial} ({d.state})
                      </option>
                    ))}
                  </select>
                  <div className="absolute right-3 top-1/2 -translate-y-1/2">
                    <RefreshCw 
                      size={10} 
                      className="text-slate-600 cursor-pointer hover:text-accent-primary transition-colors" 
                      onClick={(e) => { e.stopPropagation(); loadDevices(); }} 
                    />
                  </div>
                </div>
                {devices.length === 0 && (
                  <div className="text-[8px] text-amber-500/80 font-bold uppercase flex items-center gap-1">
                    <div className="w-1 h-1 rounded-full bg-amber-500 animate-pulse" />
                    No ADB Devices Found
                  </div>
                )}
              </div>

              {/* Dynamic Analysis Toggle */}
              <div 
                className={clsx(
                  "flex items-center justify-between p-3 rounded-xl border transition-all",
                  devices.length > 0 ? "bg-bg-primary/40 border-bg-border cursor-pointer hover:border-accent-primary/40" : "bg-amber-500/5 border-amber-500/10 opacity-60 cursor-not-allowed"
                )}
                onClick={() => devices.length > 0 && setRunDynamic(!runDynamic)}
              >
                <div className="flex flex-col">
                  <span className="text-[10px] font-black text-slate-400 uppercase tracking-tight">Forensic Deep Scan</span>
                  <span className={clsx("text-[8px] uppercase font-bold", devices.length > 0 ? "text-emerald-500" : "text-amber-500")}>
                    {devices.length > 0 ? 'Device Ready' : 'Connect Device'}
                  </span>
                </div>
                <div className={clsx(
                  "relative w-10 h-5 rounded-full transition-all duration-500",
                  runDynamic && devices.length > 0 ? 'bg-accent-primary' : 'bg-slate-800'
                )}>
                  <div className={clsx(
                    "absolute top-1 w-3 h-3 rounded-full transition-all duration-500 shadow-lg",
                    runDynamic && devices.length > 0 ? 'left-6 bg-white' : 'left-1 bg-slate-500'
                  )} />
                </div>
              </div>

              {/* MobSF Deep Scan Toggle */}
              <div 
                className={clsx(
                  "flex items-center justify-between p-3 rounded-xl border transition-all",
                  mobsfAvailable === true ? "bg-bg-primary/40 border-bg-border cursor-pointer hover:border-accent-primary/40" : "bg-red-500/5 border-red-500/10 opacity-60 cursor-not-allowed"
                )}
                onClick={() => mobsfAvailable && setUseMobsf(!useMobsf)}
              >
                <div className="flex flex-col">
                  <span className="text-[10px] font-black text-slate-400 uppercase tracking-tight">Deep MobSF Scan</span>
                  <span className={clsx("text-[8px] uppercase font-bold", mobsfAvailable === true ? "text-emerald-500" : "text-red-500")}>
                    {mobsfAvailable === null ? 'Checking Server...' : mobsfAvailable ? 'Server Online' : 'Server Offline'}
                  </span>
                </div>
                <div className={clsx(
                  "relative w-10 h-5 rounded-full transition-all duration-500",
                  useMobsf && mobsfAvailable ? 'bg-accent-primary' : 'bg-slate-800'
                )}>
                  <div className={clsx(
                    "absolute top-1 w-3 h-3 rounded-full transition-all duration-500 shadow-lg",
                    useMobsf && mobsfAvailable ? 'left-6 bg-white' : 'left-1 bg-slate-500'
                  )} />
                </div>
              </div>

              <button
                type="submit"
                disabled={analyzing || !file}
                className="btn-primary w-full justify-center h-11 rounded-xl shadow-glow-cyan/5"
              >
                {analyzing ? <RefreshCw size={14} className="animate-spin" /> : <Zap size={14} />}
                {analyzing ? 'Engaging...' : 'Engage Analysis'}
              </button>
            </form>
          </section>

          <section className="glass-card p-5 flex-1 overflow-hidden flex flex-col">
            <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
              <History size={12} className="text-accent-secondary" /> Archive Registry
            </h3>
            <div className="flex-1 overflow-y-auto space-y-2 pr-1 scrollbar-thin">
               {history.map(app => (
                 <div 
                   key={app.id} 
                   onClick={() => !analyzing && selectFromHistory(app)}
                   className={clsx(
                     "p-3 rounded-xl border transition-all cursor-pointer group",
                     appId === app.id ? "border-accent-primary bg-accent-primary/5" : "border-slate-800 bg-bg-primary/40 hover:border-slate-700"
                   )}
                 >
                    <div className="text-[10px] font-black text-slate-200 truncate group-hover:text-accent-primary transition-colors">{app.filename || app.id}</div>
                    <div className="flex justify-between items-center mt-2 text-[8px] font-mono text-slate-600 uppercase">
                       <span>{app.platform}</span>
                       <span>{relativeTime(app.uploaded_at)}</span>
                    </div>
                 </div>
               ))}
               {history.length === 0 && <div className="text-center py-8 text-[9px] text-slate-700 font-bold uppercase">Registry Empty</div>}
            </div>
          </section>
        </div>

        {/* Main Content: Progress or Report */}
        <div className="lg:col-span-3 flex flex-col gap-6">
          {analyzing && !report && (
            <>
              <MobileXRayHUD activePhase={activePhase} progress={progress} />
              <MobileReportViewer report={null} appId={appId} initialTab="aegis" deviceId={selectedDevice} />
            </>
          )}

          {!report && !analyzing && selectedDevice && (
            <PackageList 
              packages={packages} 
              onIngest={handlePackageIngest} 
            />
          )}

          {!report && !analyzing && !selectedDevice && (
            <div className="flex-1 glass-card border-dashed flex flex-col items-center justify-center py-32 opacity-30">
              <div className="relative mb-6">
                <Layers size={64} className="text-slate-700" />
                <div className="absolute inset-0 bg-slate-500/10 blur-3xl rounded-full" />
              </div>
              <p className="text-sm font-black uppercase tracking-[0.2em] text-slate-600">Awaiting Forensic Artifact</p>
              <p className="text-[10px] text-slate-700 mt-2 font-mono">STANDBY_FOR_UPLOAD_VECTOR</p>
            </div>
          )}

          {report && (
            <MobileReportViewer report={report} appId={appId} deviceId={selectedDevice} />
          )}
        </div>
      </div>
    </div>
  )
}
