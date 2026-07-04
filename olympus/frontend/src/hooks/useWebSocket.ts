import { useEffect, useRef, useCallback } from 'react'
import type { WSEvent } from '../types'

export function useWebSocket(missionId: string | null, onEvent: (e: WSEvent) => void) {
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  const connect = useCallback(() => {
    if (!missionId) return

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${window.location.host}/ws/${missionId}`

    try {
      const socket = new WebSocket(url)

      socket.onopen = () => {
        clearTimeout(reconnectTimer.current)
      }

      socket.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data) as WSEvent
          onEventRef.current(data)
        } catch {}
      }

      socket.onclose = (e) => {
        if (e.code !== 1000) {
          reconnectTimer.current = setTimeout(connect, 3000)
        }
      }

      socket.onerror = () => {
        socket.close()
      }

      ws.current = socket
    } catch {}
  }, [missionId])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      ws.current?.close(1000)
      ws.current = null
    }
  }, [connect])
}
