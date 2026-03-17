import { useEffect, useRef, useCallback } from 'react'

export function useWebSocket(onMessage) {
  const ws = useRef(null)
  const reconnectTimer = useRef(null)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    const url = `ws://${window.location.hostname}:8000/ws/logs`
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
