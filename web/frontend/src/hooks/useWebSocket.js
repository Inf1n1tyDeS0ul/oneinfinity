import { useEffect, useRef, useCallback } from 'react'

export function useWebSocket(onMessage) {
  const ws = useRef(null)
  const reconnectTimer = useRef(null)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const connect = useCallback(async () => {
    // Use same host:port as the current page (works whether served via Vite proxy or directly)
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host = window.location.host  // includes port if non-standard
    // Fetch token for WebSocket auth (query param — browsers can't set WS headers)
    let tokenParam = ''
    try {
      const r = await fetch('/api/auth-token')
      if (r.ok) {
        const { token } = await r.json()
        tokenParam = `?token=${encodeURIComponent(token)}`
      }
    } catch {}
    const url = `${proto}://${host}/ws/logs${tokenParam}`
    const socket = new WebSocket(url)
    ws.current = socket

    socket.onopen = () => {
      console.log('[WS] Connected')
    }

    socket.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        onMessageRef.current(data)
      } catch {}
    }

    socket.onclose = () => {
      console.log('[WS] Disconnected — reconnecting in 3s')
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    socket.onerror = () => {
      socket.close()
    }
  }, [])

  useEffect(() => {
    connect()
    // Ping every 25s to keep alive
    const ping = setInterval(() => {
      if (ws.current?.readyState === WebSocket.OPEN) {
        ws.current.send('ping')
      }
    }, 25000)
    return () => {
      clearInterval(ping)
      clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [connect])

  return ws
}
