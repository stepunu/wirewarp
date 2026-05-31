/**
 * Realtime event channel: WS connection to /ws/dashboard that pushes
 * `{type, ...}` events the server emits whenever DB state mutates. Each
 * event is treated as a hint to invalidate one or more React Query
 * keys — the queries refetch via the normal REST endpoints, so we don't
 * duplicate response schemas across HTTP and WS.
 *
 * Auth: JWT in `?token=` query param (matches /ws/agent posture). If
 * the token is missing we don't even open the socket; the server
 * routes the user to /login when REST calls fail anyway.
 *
 * Failure modes:
 *  - WS dies: reconnect with jittered exponential backoff. While dead,
 *    a 30s safety-poll fires `invalidateQueries()` so eventual
 *    consistency holds even without push.
 *  - Server sends `desync`: assume we missed N events, invalidate
 *    everything.
 */
import type { QueryClient } from '@tanstack/react-query'

type EventHandler = (payload: Record<string, unknown>) => void

const eventToKeys: Record<string, string[][]> = {
  'agent.changed': [['agents'], ['nodes']],
  'edge.changed': [['nodes'], ['node-edge'], ['edge-capabilities'], ['edge-policy'], ['edge-routes'], ['edge-cache'], ['edge-rendered'], ['edge-versions'], ['edge-fragments'], ['security-overview'], ['sites'], ['server-edge-policy'], ['edge-profiles']],
  'edge.access': [['edge-access-events'], ['node-edge-access'], ['security-overview']],
  'tunnel_server.changed': [['tunnel-servers'], ['tunnel-server-ips'], ['tunnel-server-summary'], ['nodes']],
  'tunnel_client.changed': [['tunnel-clients'], ['tunnel-client-attachments'], ['tunnel-client-summary'], ['nodes']],
  'port_forward.changed': [['port-forwards']],
  'lan_client.changed': [['lan-clients']],
  'audit.changed': [['audit']],
  'heal_event.changed': [['heal-events'], ['tunnel-server-summary'], ['tunnel-client-summary']],
  'wg_peer.changed': [['wg-peers'], ['tunnel-server-summary'], ['tunnel-client-summary']],
  'crowdsec.changed': [['crowdsec'], ['node-edge'], ['nodes']],
  'security.changed': [['security-overview'], ['security-events'], ['security-event-groups'], ['sites'], ['node-edge'], ['server-edge-policy']],
  'traefik.changed': [['traefik'], ['node-edge'], ['nodes']],
}

interface MountOpts {
  queryClient: QueryClient
  getToken: () => string | null
  /** Called when the socket connects/disconnects. Used by callers to
   *  drive a connection-state indicator in the UI if they want one. */
  onConnectionChange?: (connected: boolean) => void
  /** Catch-all for events that don't map cleanly to query
   *  invalidations (e.g. transient notices like dns.synced). Receives
   *  the full event payload. */
  onEvent?: (event: Record<string, unknown>) => void
}

export function mountRealtime(opts: MountOpts): () => void {
  const { queryClient, getToken, onConnectionChange, onEvent } = opts

  let ws: WebSocket | null = null
  let backoff = 1000
  const maxBackoff = 30_000
  let reconnectTimer: number | null = null
  let safetyPollTimer: number | null = null
  let stopped = false
  let connected = false

  const setConnected = (v: boolean) => {
    if (connected === v) return
    connected = v
    onConnectionChange?.(v)
    if (v) {
      stopSafetyPoll()
    } else {
      startSafetyPoll()
    }
  }

  // While the WS is dead, fire a coarse invalidate-all every 30s so
  // pages eventually catch up. Skipped while the socket is healthy.
  const startSafetyPoll = () => {
    if (safetyPollTimer != null) return
    safetyPollTimer = window.setInterval(() => {
      queryClient.invalidateQueries()
    }, 30_000)
  }
  const stopSafetyPoll = () => {
    if (safetyPollTimer != null) {
      window.clearInterval(safetyPollTimer)
      safetyPollTimer = null
    }
  }

  const handlers: Record<string, EventHandler> = {
    desync: () => queryClient.invalidateQueries(),
    ready: () => {
      // Initial sync: invalidate everything so every mounted query
      // refetches against the freshest state once we're plugged in.
      queryClient.invalidateQueries()
    },
  }

  for (const [type, keys] of Object.entries(eventToKeys)) {
    handlers[type] = () => {
      for (const k of keys) queryClient.invalidateQueries({ queryKey: k })
    }
  }

  const connect = () => {
    if (stopped) return
    const token = getToken()
    if (!token) {
      // No auth → no WS. Fall back to safety poll so the UI still
      // works even before login finishes wiring things up.
      startSafetyPoll()
      return
    }

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${proto}//${window.location.host}/ws/dashboard?token=${encodeURIComponent(token)}`

    try {
      ws = new WebSocket(url)
    } catch {
      scheduleReconnect()
      return
    }

    ws.onopen = () => {
      backoff = 1000
      setConnected(true)
    }

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as Record<string, unknown>
        const type = msg.type
        if (typeof type !== 'string') return
        const handler = handlers[type]
        if (handler) handler(msg)
        // Always forward to the catch-all so callers can react to events
        // that aren't in the invalidation map (e.g. dns.synced toasts).
        onEvent?.(msg)
      } catch {
        // ignore malformed frame
      }
    }

    ws.onerror = () => {
      // onerror is followed by onclose; the close handler does the work.
    }

    ws.onclose = () => {
      setConnected(false)
      ws = null
      scheduleReconnect()
    }
  }

  const scheduleReconnect = () => {
    if (stopped) return
    if (reconnectTimer != null) return
    const delay = backoff * (0.75 + Math.random() * 0.5)
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null
      connect()
    }, delay)
    backoff = Math.min(backoff * 2, maxBackoff)
  }

  connect()

  return () => {
    stopped = true
    stopSafetyPoll()
    if (reconnectTimer != null) window.clearTimeout(reconnectTimer)
    if (ws) {
      try {
        ws.close()
      } catch {
        // ignore
      }
    }
  }
}
