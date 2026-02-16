import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { portForwards, tunnelServers, tunnelClients, serviceTemplates, agents } from '../lib/api'
import type { PortForward, ServiceTemplate } from '../lib/types'

export default function PortForwards() {
  const qc = useQueryClient()
  const { data: pfs = [] } = useQuery({ queryKey: ['port-forwards'], queryFn: () => portForwards.list() })
  const { data: servers = [] } = useQuery({ queryKey: ['tunnel-servers'], queryFn: tunnelServers.list })
  const { data: clients = [] } = useQuery({ queryKey: ['tunnel-clients'], queryFn: tunnelClients.list })
  const { data: templates = [] } = useQuery({ queryKey: ['service-templates'], queryFn: serviceTemplates.list })
  const { data: agentList = [] } = useQuery({ queryKey: ['agents'], queryFn: agents.list })

  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({
    tunnel_server_id: '', tunnel_client_id: '', protocol: 'tcp' as 'tcp' | 'udp',
    public_port: '', destination_ip: '', destination_port: '', description: '',
  })

  const create = useMutation({
    mutationFn: () => portForwards.create({
      ...form,
      public_port: +form.public_port,
      destination_port: +form.destination_port,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['port-forwards'] }); setShowAdd(false); resetForm() },
  })

  const toggle = useMutation({
    mutationFn: (pf: PortForward) => portForwards.update(pf.id, { active: !pf.active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['port-forwards'] }),
  })

  const del = useMutation({
    mutationFn: portForwards.del,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['port-forwards'] }),
  })

  function resetForm() {
    setForm({ tunnel_server_id: '', tunnel_client_id: '', protocol: 'tcp', public_port: '', destination_ip: '', destination_port: '', description: '' })
  }

  function applyTemplate(t: ServiceTemplate) {
    // Parse ports string like "2302-2305,27016"
    const parts = t.ports.split(',').map(s => s.trim())
    const firstPort = parts[0].includes('-') ? parts[0].split('-')[0] : parts[0]
    setForm({
      ...form,
      protocol: t.protocol === 'both' ? 'tcp' : t.protocol as 'tcp' | 'udp',
      public_port: firstPort,
      destination_port: firstPort,
      description: t.name,
    })
  }

  function agentName(agentId: string) {
    const a = agentList.find(x => x.id === agentId)
    return a?.name || a?.hostname || agentId.slice(0, 8)
  }

  // Group by server
  const grouped = servers.map(s => ({
    server: s,
    name: agentName(s.agent_id),
    rules: pfs.filter(p => p.tunnel_server_id === s.id),
  }))

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Port Forwards</h1>
        <button onClick={() => { setShowAdd(true); resetForm() }}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium">
          Add Forward
        </button>
      </div>

      {grouped.map(g => (
        <div key={g.server.id} className="mb-6">
          <h2 className="text-lg font-semibold text-white mb-2">{g.name} <span className="text-gray-400 text-sm font-normal">({g.server.public_ip || g.server.tunnel_network})</span></h2>
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400">
                  <th className="text-left px-4 py-2 font-medium">Protocol</th>
                  <th className="text-left px-4 py-2 font-medium">Public Port</th>
                  <th className="text-left px-4 py-2 font-medium">Destination</th>
                  <th className="text-left px-4 py-2 font-medium">Description</th>
                  <th className="text-left px-4 py-2 font-medium">Active</th>
                  <th className="text-right px-4 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {g.rules.map(pf => (
                  <tr key={pf.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-2 text-gray-300 uppercase">{pf.protocol}</td>
                    <td className="px-4 py-2 text-white font-mono">{pf.public_port}</td>
                    <td className="px-4 py-2 text-gray-300 font-mono">{pf.destination_ip}:{pf.destination_port}</td>
                    <td className="px-4 py-2 text-gray-400">{pf.description || '-'}</td>
                    <td className="px-4 py-2">
                      <button onClick={() => toggle.mutate(pf)}
                        className={`w-10 h-5 rounded-full relative transition-colors ${pf.active ? 'bg-green-600' : 'bg-gray-700'}`}>
                        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${pf.active ? 'left-5' : 'left-0.5'}`} />
                      </button>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button onClick={() => { if (confirm('Delete this forward?')) del.mutate(pf.id) }}
                        className="text-red-400 hover:text-red-300 text-xs">Delete</button>
                    </td>
                  </tr>
                ))}
                {g.rules.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-4 text-center text-gray-500 text-sm">No port forwards</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ))}

      {grouped.length === 0 && <p className="text-gray-500">No tunnel servers available. Register a server agent first.</p>}

      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 w-full max-w-lg">
            <h2 className="text-lg font-bold text-white mb-4">Add Port Forward</h2>

            {templates.length > 0 && (
              <div className="mb-4">
                <span className="text-xs text-gray-400 block mb-1">Apply Template</span>
                <div className="flex gap-2 flex-wrap">
                  {templates.map(t => (
                    <button key={t.id} onClick={() => applyTemplate(t)}
                      className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700">
                      {t.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs text-gray-400">Tunnel Server</span>
                <select value={form.tunnel_server_id} onChange={e => setForm({ ...form, tunnel_server_id: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white">
                  <option value="">-- Select --</option>
                  {servers.map(s => <option key={s.id} value={s.id}>{agentName(s.agent_id)}</option>)}
                </select>
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">Tunnel Client</span>
                <select value={form.tunnel_client_id} onChange={e => setForm({ ...form, tunnel_client_id: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white">
                  <option value="">-- Select --</option>
                  {clients.map(c => <option key={c.id} value={c.id}>{agentName(c.agent_id)} ({c.tunnel_ip || '-'})</option>)}
                </select>
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">Protocol</span>
                <select value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value as 'tcp' | 'udp' })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">Public Port</span>
                <input type="number" value={form.public_port} onChange={e => setForm({ ...form, public_port: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">Destination IP</span>
                <input value={form.destination_ip} onChange={e => setForm({ ...form, destination_ip: e.target.value })}
                  placeholder="e.g. 10.0.0.2"
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">Destination Port</span>
                <input type="number" value={form.destination_port} onChange={e => setForm({ ...form, destination_port: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
              </label>
              <label className="block col-span-2">
                <span className="text-xs text-gray-400">Description (optional)</span>
                <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
              </label>
            </div>

            <div className="flex gap-2 justify-end mt-4">
              <button onClick={() => setShowAdd(false)} className="text-sm text-gray-400 hover:text-white px-3 py-1">Cancel</button>
              <button onClick={() => create.mutate()} disabled={create.isPending}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
