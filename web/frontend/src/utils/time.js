export function relativeTime(iso) {
  if (!iso) return '—'
  try {
    // Handle Unix timestamps (seconds or milliseconds) and ISO strings
    let d
    if (typeof iso === 'number' || /^\d+$/.test(String(iso))) {
      const n = Number(iso)
      d = new Date(n < 1e12 ? n * 1000 : n)
    } else {
      const s = String(iso)
      d = new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z')
    }
    
    if (isNaN(d.getTime())) return String(iso)

    const diff = Date.now() - d.getTime()
    const mins = Math.floor(diff / 60000)
    
    if (mins < 1) return 'just now'
    if (mins < 60) return `${mins}m ago`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `${hrs}h ago`
    const days = Math.floor(hrs / 24)
    if (days < 30) return `${days}d ago`
    
    // Fallback to formatted date for older entries
    const dd = String(d.getDate()).padStart(2, '0')
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const yyyy = d.getFullYear()
    return `${dd}-${mm}-${yyyy}`
  } catch {
    return String(iso)
  }
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  try {
    let d
    if (typeof iso === 'number' || /^\d+$/.test(String(iso))) {
      const n = Number(iso)
      d = new Date(n < 1e12 ? n * 1000 : n)
    } else {
      const s = String(iso)
      d = new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z')
    }
    if (isNaN(d.getTime())) return String(iso)
    const dd = String(d.getDate()).padStart(2, '0')
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const yyyy = d.getFullYear()
    const hh = String(d.getHours()).padStart(2, '0')
    const min = String(d.getMinutes()).padStart(2, '0')
    const ss = String(d.getSeconds()).padStart(2, '0')
    return `${dd}-${mm}-${yyyy} ${hh}:${min}:${ss}`
  } catch { return String(iso) }
}
