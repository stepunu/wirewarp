import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { tunnelClients, tunnelServers, agents } from '../lib/api'
import type { TunnelClient } from '../lib/types'
import StatusBadge from '../components/StatusBadge'

export default function TunnelClients() {
  const qc = useQueryClient()
  const { data: clients = [] } = useQuery({ queryKey: ['tunnel-clients'], queryFn: tunnelClients.list })
  const { data: servers = [] } = useQuery({ queryKey: ['tunnel-servers'], queryFn: tunnelServers.list })
  const { data: agentList = [] } = useQuery({ queryKey: ['agents'], queryFn: agents.list })

  const [editing, setEditing] = useState<string | null>(null)
  const [form, setForm] = useState({ tunnel_server_id: '', tunnel_ip: '', vm_network: '', lan_ip: '', is_gateway: false })

  const update = useMutation({
    mutationFn: (c: TunnelClient) => tunnelClients.update(c.id, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tunnel-clients'] }); setEditing(null) },
  })

  const del = useMutation({
    mutationFn: tunnelClients.del,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tunnel-clients'] }); setEditing(null) },
  })

  function startEdit(c: TunnelClient) {
    setEditing(c.id)
    setForm({
      tunnel_server_id: c.tunnel_server_id || '',
      tunnel_ip: c.tunnel_ip || '',
      vm_network: c.vm_network || '',
      lan_ip: c.lan_ip || '',
      is_gateway: c.is_gateway,
    })
  }

  function agentName(agentId: string) {
    const a = agentList.find((x) => x.id === agentId)
    return a?.name || a?.hostname || agentId.slice(0, 8)
  }

  function serverLabel(serverId: string | null) {
    if (!serverId) return '-'
    const s = servers.find((x) => x.id === serverId)
    if (!s) return serverId.slice(0, 8)
    return agentName(s.agent_id) + ` (${s.public_ip || s.tunnel_network})`
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Tunnel Clients</h1>

      {clients.length === 0 && <p className="text-gray-500">No tunnel clients configured. Register a client agent first.</p>}

      <div className="space-y-4">
        {clients.map((c) => (
          <div key={c.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <h2 className="text-white font-semibold">{agentName(c.agent_id)}</h2>
                <StatusBadge status={c.status} />
                {c.is_gateway && <span className="text-xs bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded">Gateway</span>}
              </div>
              {editing !== c.id && (
                <button onClick={() => startEdit(c)} className="text-blue-400 hover:text-blue-300 text-sm">Edit</button>
              )}
            </div>

            {editing === c.id ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="text-xs text-gray-400">Connect to Server</span>
                    <select value={form.tunnel_server_id} onChange={(e) => setForm({ ...form, tunnel_server_id: e.target.value })}
                      className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white">
                      <option value="">-- Select --</option>
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>{agentName(s.agent_id)} ({s.public_ip || s.tunnel_network})</option>
                      ))}
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-xs text-gray-400">Tunnel IP</span>
                    <input value={form.tunnel_ip} onChange={(e) => setForm({ ...form, tunnel_ip: e.target.value })}
                      placeholder="e.g. 10.0.0.2"
                      className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                  </label>
                </div>

                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={form.is_gateway} onChange={(e) => setForm({ ...form, is_gateway: e.target.checked })}
                    className="rounded border-gray-600" />
                  <span className="text-sm text-gray-300">Is Gateway</span>
                  <span className="text-xs text-gray-500" title="Enable if this client routes traffic for other LAN devices through the tunnel">(routes LAN traffic through tunnel)</span>
                </label>

                {form.is_gateway && (
                  <div className="grid grid-cols-2 gap-3">
                    <label className="block">
                      <span className="text-xs text-gray-400">LAN Network</span>
                      <input value={form.vm_network} onChange={(e) => setForm({ ...form, vm_network: e.target.value })}
                        placeholder="e.g. 192.168.20.0/24"
                        className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                    </label>
                    <label className="block">
                      <span className="text-xs text-gray-400">LAN IP</span>
                      <input value={form.lan_ip} onChange={(e) => setForm({ ...form, lan_ip: e.target.value })}
                        placeholder="e.g. 192.168.20.110"
                        className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                    </label>
                  </div>
                )}

                <div className="flex gap-2 justify-between mt-2">
                  <button onClick={() => { if (confirm('Delete this tunnel client?')) del.mutate(c.id) }}
                    className="text-sm text-red-400 hover:text-red-300 px-3 py-1">Delete</button>
                  <div className="flex gap-2">
                    <button onClick={() => setEditing(null)} className="text-sm text-gray-400 hover:text-white px-3 py-1">Cancel</button>
                    <button onClick={() => update.mutate(c)} className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">Save</button>
                  </div>
                </div>
              </div>
            ) : (
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-y-2 text-sm">
                <div><span className="text-gray-400">Server:</span> <span className="text-white ml-1">{serverLabel(c.tunnel_server_id)}</span></div>
                <div><span className="text-gray-400">Tunnel IP:</span> <span className="text-white ml-1">{c.tunnel_ip || '-'}</span></div>
                <div><span className="text-gray-400">LAN Network:</span> <span className="text-white ml-1">{c.vm_network || '-'}</span></div>
                <div><span className="text-gray-400">LAN IP:</span> <span className="text-white ml-1">{c.lan_ip || '-'}</span></div>
                <div><span className="text-gray-400">Public Key:</span> <span className="text-white ml-1 font-mono text-xs">{c.wg_public_key ? c.wg_public_key.slice(0, 16) + '...' : '-'}</span></div>
              </dl>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
