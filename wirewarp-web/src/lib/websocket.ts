import { create } from 'zustand'
import type { Agent } from './types'

interface WSState {
  agents: Map<string, Agent>
  connected: boolean
  updateAgent: (agent: Agent) => void
  setAgents: (agents: Agent[]) => void
}

export const useWSStore = create<WSState>((set) => ({
  agents: new Map(),
  connected: false,
  updateAgent: (agent) =>
    set((s) => {
      const next = new Map(s.agents)
      next.set(agent.id, agent)
      return { agents: next }
    }),
  setAgents: (agents) =>
    set(() => {
      const m = new Map<string, Agent>()
      for (const a of agents) m.set(a.id, a)
      return { agents: m }
    }),
}))

let ws: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

export function connectWS(token: string) {
  if (ws) return

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${proto}//${window.location.host}/ws/dashboard?token=${encodeURIComponent(token)}`

  ws = new WebSocket(url)

  ws.onopen = () => {
    useWSStore.setState({ connected: true })
  }

  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data)
      if (msg.type === 'agent_status') {
        useWSStore.getState().updateAgent(msg.agent)
      }
    } catch {
      // ignore non-JSON messages
    }
  }

  ws.onclose = () => {
    ws = null
    useWSStore.setState({ connected: false })
    reconnectTimer = setTimeout(() => connectWS(token), 5000)
  }

  ws.onerror = () => {
    ws?.close()
  }
}

export function disconnectWS() {
  if (reconnectTimer) clearTimeout(reconnectTimer)
  ws?.close()
  ws = null
}
