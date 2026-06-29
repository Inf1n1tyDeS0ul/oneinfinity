import React, { useState } from 'react'
import {
  Code2, Terminal, ShieldOff, TrendingUp, Copy, Check,
  ChevronDown, Loader2, Zap, Lock, Package
} from 'lucide-react'
import api from '../utils/api'
import clsx from 'clsx'

// ─── Constants ────────────────────────────────────────────────────────────────

const PAYLOAD_TYPES = [
  { value: 'shellcode',    label: 'Shellcode (raw)' },
  { value: 'exe',         label: 'PE Executable' },
  { value: 'dll',         label: 'DLL Reflective' },
  { value: 'powershell',  label: 'PowerShell Stager' },
  { value: 'macro',       label: 'Office Macro' },
  { value: 'hta',         label: 'HTA Drop' },
]

const SHELL_TYPES = [
  { value: 'shell_reverse_tcp',  label: 'Reverse TCP Shell' },
  { value: 'shell_bind_tcp',     label: 'Bind TCP Shell' },
  { value: 'cmd_reverse',        label: 'cmd.exe Reverse' },
  { value: 'powershell_reverse', label: 'PS Reverse Shell' },
]

const BYPASS_TYPES = [
  { value: 'waf_generic',    label: 'Generic WAF Evasion' },
  { value: 'cloudflare',     label: 'Cloudflare Bypass' },
  { value: '403_forbidden',  label: '403 Forbidden Bypass' },
  { value: 'ip_rotation',    label: 'IP Rotation Headers' },
  { value: 'encoding',       label: 'Encoding Tricks' },
]

const PRIVESC_TYPES = [
  { value: 'suid_abuse',      label: 'SUID Binary Abuse' },
  { value: 'sudo_misconfig',  label: 'Sudo Misconfiguration' },
  { value: 'cron_hijack',     label: 'Cron Job Hijacking' },
  { value: 'path_injection',  label: 'PATH Injection' },
  { value: 'docker_escape',   label: 'Docker Escape' },
  { value: 'kernel_exploit',  label: 'Kernel Exploit Loader' },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function SectionCard({ icon: Icon, title, subtitle, accent, children }) {
  return (
    <div className={clsx(
      'card',
      accent && 'ring-1 ring-accent-primary/20'
    )}>
      <div className="card-header">
        <div className="card-title">
          <Icon size={13} className={accent ? 'text-accent-primary' : 'text-slate-400'} />
          {title}
        </div>
        {subtitle && <span className="text-[10px] text-slate-600">{subtitle}</span>}
      </div>
      <div className="p-4 flex flex-col gap-3">
        {children}
      </div>
    </div>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <button
      onClick={handleCopy}
      className="btn-icon shrink-0 text-slate-500 hover:text-accent-primary p-1"
      title="Copy to clipboard"
    >
      {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
    </button>
  )
}

function ResultBlock({ result, loading }) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 justify-center text-slate-500 text-xs">
        <Loader2 size={14} className="animate-spin text-accent-primary" />
        Generating…
      </div>
    )
  }
  if (!result) return null
  const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2)
  return (
    <div className="relative group rounded-xl bg-bg-primary/60 border border-bg-border overflow-hidden">
      <div className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <CopyButton text={text} />
      </div>
      <pre className="text-[11px] font-mono text-emerald-300 p-4 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72 scrollbar-thin">
        {text}
      </pre>
    </div>
  )
}

function SelectInput({ value, onChange, options, label }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-black uppercase tracking-widest text-slate-500">{label}</label>
      <div className="relative">
        <select
          value={value}
          onChange={e => onChange(e.target.value)}
          className="w-full bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-xs text-slate-300 outline-none focus:border-accent-primary appearance-none pr-8 cursor-pointer"
        >
          {options.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <ChevronDown size={11} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
      </div>
    </div>
  )
}

function TextInput({ value, onChange, placeholder, label }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-black uppercase tracking-widest text-slate-500">{label}</label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-accent-primary"
      />
    </div>
  )
}

function GenerateButton({ onClick, loading, label = 'Generate' }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={clsx(
        'flex items-center gap-1.5 text-xs font-bold px-4 py-2 rounded-xl self-start transition-all',
        loading
          ? 'bg-accent-primary/20 text-accent-primary/60 cursor-not-allowed'
          : 'bg-accent-primary/10 hover:bg-accent-primary/20 text-accent-primary border border-accent-primary/30 hover:border-accent-primary/60'
      )}
    >
      {loading
        ? <Loader2 size={12} className="animate-spin" />
        : <Zap size={12} />
      }
      {label}
    </button>
  )
}

// ─── Section: Payload Generator ──────────────────────────────────────────────

function PayloadGenerator() {
  const [context, setContext]       = useState('')
  const [payloadType, setPayloadType] = useState(PAYLOAD_TYPES[0].value)
  const [result, setResult]         = useState(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  const generate = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.post('/arsenal/payload', { payload_type: payloadType, context })
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <SectionCard icon={Code2} title="Payload Generator" subtitle="Nim-compiled offensive payloads" accent>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <SelectInput
          label="Payload Type"
          value={payloadType}
          onChange={setPayloadType}
          options={PAYLOAD_TYPES}
        />
        <TextInput
          label="Context / LHOST:LPORT"
          value={context}
          onChange={setContext}
          placeholder="e.g. 192.168.1.10:4444"
        />
      </div>
      <GenerateButton onClick={generate} loading={loading} label="Generate Payload" />
      {error && <div className="text-xs text-red-400 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">{error}</div>}
      <ResultBlock result={result} loading={loading} />
    </SectionCard>
  )
}

// ─── Section: Shell Generator ─────────────────────────────────────────────────

function ShellGenerator() {
  const [lhost, setLhost]           = useState('')
  const [lport, setLport]           = useState('4444')
  const [shellType, setShellType]   = useState(SHELL_TYPES[0].value)
  const [result, setResult]         = useState(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  const generate = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.post('/arsenal/payload', {
        payload_type: shellType,
        context: `${lhost}:${lport}`,
      })
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <SectionCard icon={Terminal} title="Shell Generator" subtitle="Reverse and bind shells">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <SelectInput
          label="Shell Type"
          value={shellType}
          onChange={setShellType}
          options={SHELL_TYPES}
        />
        <TextInput
          label="LHOST"
          value={lhost}
          onChange={setLhost}
          placeholder="192.168.1.10"
        />
        <TextInput
          label="LPORT"
          value={lport}
          onChange={setLport}
          placeholder="4444"
        />
      </div>
      <GenerateButton onClick={generate} loading={loading} label="Generate Shell" />
      {error && <div className="text-xs text-red-400 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">{error}</div>}
      <ResultBlock result={result} loading={loading} />
    </SectionCard>
  )
}

// ─── Section: WAF / 403 Bypass ────────────────────────────────────────────────

function WafBypass() {
  const [url, setUrl]               = useState('')
  const [bypassType, setBypassType] = useState(BYPASS_TYPES[0].value)
  const [result, setResult]         = useState(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  const generate = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.post('/arsenal/bypass', { url: url.trim(), bypass_type: bypassType })
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <SectionCard icon={ShieldOff} title="WAF / 403 Bypass" subtitle="Evasion variants against common WAFs">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <TextInput
          label="Target URL"
          value={url}
          onChange={setUrl}
          placeholder="https://target.example.com/admin"
        />
        <SelectInput
          label="Bypass Type"
          value={bypassType}
          onChange={setBypassType}
          options={BYPASS_TYPES}
        />
      </div>
      <GenerateButton onClick={generate} loading={loading} label="Find Bypass Variants" />
      {error && <div className="text-xs text-red-400 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">{error}</div>}
      {!loading && result && (() => {
        const variants = Array.isArray(result?.variants)
          ? result.variants
          : Array.isArray(result)
          ? result
          : null
        if (variants) {
          return (
            <div className="flex flex-col gap-2">
              <div className="text-[10px] font-black uppercase tracking-widest text-slate-500">
                {variants.length} Bypass Variant{variants.length !== 1 ? 's' : ''} Found
              </div>
              {variants.map((v, i) => (
                <div key={i} className="relative group flex items-start gap-3 rounded-xl bg-bg-primary/60 border border-bg-border px-4 py-2.5">
                  <span className="text-[10px] font-mono text-slate-500 shrink-0 mt-0.5 w-4">{i + 1}.</span>
                  <span className="text-xs font-mono text-emerald-300 break-all">{typeof v === 'object' ? JSON.stringify(v) : v}</span>
                  <div className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <CopyButton text={typeof v === 'object' ? JSON.stringify(v) : v} />
                  </div>
                </div>
              ))}
            </div>
          )
        }
        return <ResultBlock result={result} loading={false} />
      })()}
      {loading && <ResultBlock result={null} loading />}
    </SectionCard>
  )
}

// ─── Section: PrivEsc Techniques ─────────────────────────────────────────────

function PrivEsc() {
  const [target, setTarget]         = useState('')
  const [technique, setTechnique]   = useState(PRIVESC_TYPES[0].value)
  const [result, setResult]         = useState(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  const generate = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.post('/arsenal/payload', {
        payload_type: 'privesc',
        context: JSON.stringify({ technique, target }),
      })
      setResult(r.data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <SectionCard icon={TrendingUp} title="PrivEsc Techniques" subtitle="Local privilege escalation playbooks">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <SelectInput
          label="Technique"
          value={technique}
          onChange={setTechnique}
          options={PRIVESC_TYPES}
        />
        <TextInput
          label="Target OS / Context (optional)"
          value={target}
          onChange={setTarget}
          placeholder="e.g. Ubuntu 22.04, kernel 5.15"
        />
      </div>
      <GenerateButton onClick={generate} loading={loading} label="Generate Technique" />
      {error && <div className="text-xs text-red-400 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">{error}</div>}
      <ResultBlock result={result} loading={loading} />
    </SectionCard>
  )
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export default function Arsenal() {
  return (
    <div className="flex flex-col gap-5">
      {/* Page header */}
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <Package size={18} className="text-accent-primary" />
            Arsenal
          </div>
          <div className="text-xs text-slate-500">
            Nim payload generation · WAF bypass · Shell crafting · PrivEsc playbooks
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-black uppercase tracking-widest text-slate-600 border border-bg-border rounded-lg px-2 py-1">
            <Lock size={9} className="inline mr-1 text-slate-600" />
            Offensive
          </span>
        </div>
      </div>

      {/* Sections */}
      <PayloadGenerator />
      <ShellGenerator />
      <WafBypass />
      <PrivEsc />
    </div>
  )
}
