import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { tunnelServers, agents } from '../lib/api'
import type { TunnelServer } from '../lib/types'

export default function TunnelServers() {
  const qc = useQueryClient()
  const { data: servers = [] } = useQuery({ queryKey: ['tunnel-servers'], queryFn: tunnelServers.list })
  const { data: agentList = [] } = useQuery({ queryKey: ['agents'], queryFn: agents.list })

  const [editing, setEditing] = useState<string | null>(null)
  const [form, setForm] = useState({ wg_port: 0, public_iface: '', tunnel_network: '' })

  const update = useMutation({
    mutationFn: (s: TunnelServer) => tunnelServers.update(s.id, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tunnel-servers'] }); setEditing(null) },
  })

  function startEdit(s: TunnelServer) {
    setEditing(s.id)
    setForm({ wg_port: s.wg_port, public_iface: s.public_iface, tunnel_network: s.tunnel_network })
  }

  function agentName(agentId: string) {
    const a = agentList.find((x) => x.id === agentId)
    return a?.name || a?.hostname || agentId.slice(0, 8)
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Tunnel Servers</h1>

      {servers.length === 0 && <p className="text-gray-500">No tunnel servers configured. Register a server agent first.</p>}

      <div className="space-y-4">
        {servers.map((s) => (
          <div key={s.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold">{agentName(s.agent_id)}</h2>
              {editing !== s.id && (
                <button onClick={() => startEdit(s)} className="text-blue-400 hover:text-blue-300 text-sm">
                  Edit
                </button>
              )}
            </div>

            {editing === s.id ? (
              <div className="grid grid-cols-3 gap-3">
                <label className="block">
                  <span className="text-xs text-gray-400">WG Port</span>
                  <input type="number" value={form.wg_port} onChange={(e) => setForm({ ...form, wg_port: +e.target.value })}
                    className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Public Interface</span>
                  <input value={form.public_iface} onChange={(e) => setForm({ ...form, public_iface: e.target.value })}
                    className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Tunnel Network</span>
                  <input value={form.tunnel_network} onChange={(e) => setForm({ ...form, tunnel_network: e.target.value })}
                    className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                </label>
                <div className="col-span-3 flex gap-2 justify-end mt-2">
                  <button onClick={() => setEditing(null)} className="text-sm text-gray-400 hover:text-white px-3 py-1">Cancel</button>
                  <button onClick={() => update.mutate(s)} className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">Save</button>
                </div>
              </div>
            ) : (
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-y-2 text-sm">
                <div><span className="text-gray-400">Interface:</span> <span className="text-white ml-1">{s.wg_interface}</span></div>
                <div><span className="text-gray-400">Port:</span> <span className="text-white ml-1">{s.wg_port}</span></div>
                <div><span className="text-gray-400">Public IP:</span> <span className="text-white ml-1">{s.public_ip || '-'}</span></div>
                <div><span className="text-gray-400">Public Iface:</span> <span className="text-white ml-1">{s.public_iface}</span></div>
                <div><span className="text-gray-400">Network:</span> <span className="text-white ml-1">{s.tunnel_network}</span></div>
                <div><span className="text-gray-400">Public Key:</span> <span className="text-white ml-1 font-mono text-xs">{s.wg_public_key ? s.wg_public_key.slice(0, 16) + '...' : '-'}</span></div>
              </dl>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
