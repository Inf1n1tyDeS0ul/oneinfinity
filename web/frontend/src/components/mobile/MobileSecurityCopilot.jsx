import React, { useState, useRef, useEffect } from 'react'
import { Bot, Send, Sparkles, Copy, ChevronDown, AlertTriangle, Shield, Zap, FileText } from 'lucide-react'
import { endpoints } from '../../utils/api'
import clsx from 'clsx'

const QUICK_ACTIONS = [
  { label: 'Critical Vulns', icon: AlertTriangle, prompt: 'List and explain all critical vulnerabilities found in this app, with severity justification and CVSS context.' },
  { label: 'Exploit PoC', icon: Zap, prompt: 'For the highest-severity vulnerability, write a proof-of-concept exploit with step-by-step instructions and expected output.' },
  { label: 'Attack Path', icon: Shield, prompt: 'Describe the most dangerous attack path an adversary could take using the discovered vulnerabilities, API endpoints, and exposed components.' },
  { label: 'HackerOne Report', icon: FileText, prompt: 'Write a professional HackerOne bug report for the most impactful vulnerability. Include: Summary, Severity, Steps to Reproduce, Impact, and Remediation.' },
  { label: 'SSL Pinning Bypass', icon: Sparkles, prompt: 'Provide a complete Frida script to bypass SSL certificate pinning in this app, tailored to the detected pinning method.' },
]

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1 px-3 py-2">
      {[0, 1, 2].map(i => (
        <div key={i} className="w-1.5 h-1.5 rounded-full bg-accent-primary/60 animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }} />
      ))}
    </div>
  )
}

function MessageBubble({ msg }) {
  const [copied, setCopied] = useState(false)
  const isUser = msg.role === 'user'

  const copy = () => {
    navigator.clipboard.writeText(msg.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Parse markdown-ish content: code blocks, bold
  const renderContent = (text) => {
    const parts = text.split(/(```[\s\S]*?```|`[^`]+`|\*\*[^*]+\*\*)/g)
    return parts.map((part, i) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const code = part.slice(3, -3).replace(/^[a-z]+\n/, '')
        return (
          <pre key={i} className="mt-2 mb-1 p-2 rounded bg-bg-primary border border-bg-border text-[10px] font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
            {code}
          </pre>
        )
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} className="px-1 py-0.5 rounded bg-bg-primary text-accent-primary text-[10px] font-mono">{part.slice(1, -1)}</code>
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i} className="text-slate-100">{part.slice(2, -2)}</strong>
      }
      return <span key={i}>{part}</span>
    })
  }

  return (
    <div className={clsx('group flex gap-2', isUser ? 'justify-end' : 'justify-start')}>
      {!isUser && (
        <div className="w-6 h-6 rounded-full bg-accent-primary/20 border border-accent-primary/30 flex items-center justify-center flex-shrink-0 mt-0.5">
          <Bot size={12} className="text-accent-primary" />
        </div>
      )}
      <div className={clsx(
        'max-w-[85%] rounded-lg px-3 py-2 text-xs relative',
        isUser
          ? 'bg-accent-primary/15 border border-accent-primary/30 text-slate-200'
          : 'bg-bg-secondary border border-bg-border text-slate-300'
      )}>
        <div className="leading-relaxed">{renderContent(msg.content)}</div>
        {msg.timestamp && (
          <div className="text-[9px] text-slate-600 mt-1">{msg.timestamp}</div>
        )}
        {!isUser && (
          <button
            onClick={copy}
            className="absolute top-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-white/10"
          >
            <Copy size={9} className={copied ? 'text-emerald-400' : 'text-slate-500'} />
          </button>
        )}
      </div>
    </div>
  )
}

function buildSystemContext(result) {
  if (!result) return ''
  const sc = result.severity_counts || {}
  const vulns = (result.all_vulnerabilities || []).slice(0, 10)
  const endpoints = (result.api_discovery?.endpoints || []).slice(0, 8)
  const secrets = result.secrets?.total_findings || 0

  return `You are a mobile security expert AI copilot for a bug bounty hunting platform.

App: ${result.app_name || 'Unknown'} (${result.package_name || ''})
Platform: ${result.platform || 'android'}
Risk Score: ${result.risk_score || 0}/100
Severity Counts: ${JSON.stringify(sc)}

Key Findings:
${vulns.map(v => `- [${v.severity?.toUpperCase()}] ${v.type}: ${v.detail}`).join('\n')}

API Endpoints (${endpoints.length}):
${endpoints.map(e => `- ${e.method} ${e.full_url || e.path} (auth=${e.auth_required})`).join('\n')}

Secrets Found: ${secrets}
${result.static_analysis?.debuggable ? 'App is DEBUGGABLE.' : ''}
${result.static_analysis?.cleartext_traffic ? 'Cleartext traffic ALLOWED.' : ''}
Exported Components: ${result.static_analysis?.exported_components?.length || 0}

Respond concisely and technically. Use markdown formatting. Reference specific findings when relevant.`
}

export default function MobileSecurityCopilot({ result, appName }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [showActions, setShowActions] = useState(true)
  const bottomRef = useRef()
  const inputRef = useRef()

  useEffect(() => {
    if (result && messages.length === 0) {
      const vulnCount = result.all_vulnerabilities?.length || 0
      const critCount = result.severity_counts?.critical || 0
      setMessages([{
        role: 'assistant',
        content: `Security analysis loaded for **${appName || result.app_name || 'this app'}**.\n\nFound **${vulnCount} vulnerabilities** (${critCount} critical). Risk score: **${result.risk_score || 0}/100**.\n\nAsk me anything about the findings, or use a quick action below.`,
        timestamp: new Date().toLocaleTimeString(),
      }])
    }
  }, [result])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const sendMessage = async (text) => {
    const userText = text || input.trim()
    if (!userText) return
    setInput('')
    setShowActions(false)

    const userMsg = { role: 'user', content: userText, timestamp: new Date().toLocaleTimeString() }
    setMessages(prev => [...prev, userMsg])
    setLoading(true)

    try {
      const systemCtx = buildSystemContext(result)
      const history = [...messages, userMsg].slice(-8).map(m => ({
        role: m.role, content: m.content
      }))

      const r = await endpoints.testPrompt({
        target_url: 'copilot',
        prompt: userText,
        system: systemCtx,
        messages: history,
        mode: 'copilot',
      })

      const responseText = r.data?.response || r.data?.analysis ||
        r.data?.result || 'Analysis complete. Check the findings panels for details.'

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: responseText,
        timestamp: new Date().toLocaleTimeString(),
      }])
    } catch (e) {
      // Fallback to local analysis when API unavailable
      const localResponse = generateLocalResponse(userText, result)
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: localResponse,
        timestamp: new Date().toLocaleTimeString(),
      }])
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-bg-border flex-shrink-0">
        <Bot size={13} className="text-accent-primary" />
        <span className="text-xs font-medium text-slate-300">Security Copilot</span>
        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-auto" />
        <span className="text-[10px] text-slate-500">AI</span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-3">
        {messages.length === 0 && !result && (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-center">
            <Bot size={32} className="text-accent-primary/30" />
            <div className="text-xs text-slate-500">
              Upload and analyze an app<br />to activate the Security Copilot
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <MessageBubble key={i} msg={msg} />
        ))}

        {loading && (
          <div className="flex gap-2">
            <div className="w-6 h-6 rounded-full bg-accent-primary/20 border border-accent-primary/30 flex items-center justify-center flex-shrink-0">
              <Bot size={12} className="text-accent-primary" />
            </div>
            <div className="bg-bg-secondary border border-bg-border rounded-lg">
              <TypingIndicator />
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick actions */}
      {showActions && result && (
        <div className="px-3 pb-2 flex-shrink-0">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-slate-500">Quick Actions</span>
            <button onClick={() => setShowActions(false)} className="text-[10px] text-slate-600 hover:text-slate-400">
              <ChevronDown size={10} />
            </button>
          </div>
          <div className="flex flex-col gap-1">
            {QUICK_ACTIONS.map(({ label, icon: Icon, prompt }) => (
              <button key={label}
                onClick={() => sendMessage(prompt)}
                disabled={loading}
                className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-bg-border text-[10px] text-slate-400 hover:text-slate-200 hover:border-accent-primary/40 hover:bg-accent-primary/5 transition-colors text-left"
              >
                <Icon size={10} className="text-accent-primary flex-shrink-0" />
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-3 border-t border-bg-border flex-shrink-0">
        <div className="flex gap-2 items-end">
          <textarea
            ref={inputRef}
            className="input flex-1 resize-none text-[11px] min-h-[36px] max-h-24"
            placeholder={result ? "Ask about vulnerabilities, exploits, fixes..." : "Analyze an app first..."}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKey}
            disabled={!result || loading}
            rows={1}
          />
          <button
            className="btn-primary p-2 flex-shrink-0"
            onClick={() => sendMessage()}
            disabled={!input.trim() || !result || loading}
          >
            <Send size={12} />
          </button>
        </div>
        <div className="text-[9px] text-slate-600 mt-1">Enter to send · Shift+Enter for newline</div>
      </div>
    </div>
  )
}

function generateLocalResponse(query, result) {
  if (!result) return 'No analysis data available. Please run a scan first.'

  const q = query.toLowerCase()
  const vulns = result.all_vulnerabilities || []
  const sc = result.severity_counts || {}

  if (q.includes('critical') || q.includes('most important')) {
    const critVulns = vulns.filter(v => v.severity === 'critical')
    if (!critVulns.length) return 'No critical vulnerabilities found. The app has a relatively low risk profile.'
    return `**${critVulns.length} Critical Vulnerabilities Found:**\n\n${critVulns.map((v, i) =>
      `${i + 1}. **${v.type?.replace(/_/g, ' ')}** (${v.source})\n   ${v.detail}`
    ).join('\n\n')}\n\n**Recommended action:** Address these immediately before any production deployment.`
  }

  if (q.includes('exploit') || q.includes('poc') || q.includes('proof')) {
    const highVulns = vulns.filter(v => ['critical', 'high'].includes(v.severity))
    if (!highVulns.length) return 'No high-severity vulnerabilities to exploit.'
    const v = highVulns[0]
    return `**Proof of Concept: ${v.type?.replace(/_/g, ' ')}**\n\n${
      v.type === 'debuggable_app'
        ? '```bash\n# Connect ADB and extract sensitive data\nadb shell\nam start -n com.example.app/.DebugActivity\nrun-as com.example.app cat databases/app.db\n```'
        : v.type === 'exported_component'
        ? '```bash\n# Launch exported component without authentication\nadb shell am start -n com.example.app/.ExportedActivity\n# Or via deep link\nadb shell am start -a android.intent.action.VIEW -d "app://payload"\n```'
        : v.type === 'hardcoded_secret'
        ? '```bash\n# Extract secrets from APK\napktool d app.apk -o decompiled/\ngrep -r "api_key\\|secret\\|password" decompiled/\n```'
        : `**Steps:**\n1. Identify the vulnerable endpoint/component\n2. Craft malicious input\n3. Submit and observe response\n\nVulnerability: ${v.detail}`
    }`
  }

  if (q.includes('report') || q.includes('hackerone') || q.includes('bugcrowd')) {
    const topVuln = vulns.find(v => v.severity === 'critical') || vulns[0]
    if (!topVuln) return 'No vulnerabilities to report.'
    return `**Bug Report Draft**\n\n**Title:** ${topVuln.type?.replace(/_/g, ' ')} in ${result.app_name}\n\n**Severity:** ${topVuln.severity?.toUpperCase()}\n\n**Description:**\nThe application ${result.package_name} contains a ${topVuln.type?.replace(/_/g, ' ')} vulnerability. ${topVuln.detail}\n\n**Steps to Reproduce:**\n1. Download and install the APK\n2. ${topVuln.type === 'debuggable_app' ? 'Connect ADB debugger' : 'Launch the app and navigate to the vulnerable feature'}\n3. Observe the vulnerability\n\n**Impact:**\nAn attacker could exploit this to ${topVuln.severity === 'critical' ? 'gain full access to user data and backend systems' : 'access sensitive application data'}.\n\n**Remediation:**\n${result.recommendations?.[0] || 'Apply security best practices and review the vulnerable component.'}`
  }

  if (q.includes('summary') || q.includes('overview')) {
    return `**Security Analysis Summary — ${result.app_name}**\n\n**Risk Score:** ${result.risk_score}/100\n\n**Findings:**\n- 🔴 Critical: ${sc.critical || 0}\n- 🟠 High: ${sc.high || 0}\n- 🟡 Medium: ${sc.medium || 0}\n- 🔵 Low: ${sc.low || 0}\n\n**Key Issues:**\n${vulns.slice(0, 4).map(v => `- ${v.detail}`).join('\n')}\n\n**Top Recommendation:** ${result.recommendations?.[0] || 'Review all critical findings immediately.'}`
  }

  return `**Analysis for "${query}":**\n\nBased on the scan results for ${result.app_name}:\n- Risk Score: ${result.risk_score}/100\n- ${sc.critical || 0} critical and ${sc.high || 0} high severity issues found\n\n${vulns.slice(0, 3).map(v => `• **${v.type?.replace(/_/g, ' ')}**: ${v.detail}`).join('\n')}\n\nUse the quick actions above for detailed exploit PoCs, reports, or attack paths.`
}
