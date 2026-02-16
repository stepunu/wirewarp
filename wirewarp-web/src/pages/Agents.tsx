import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { agents } from '../lib/api'
import { Link } from 'react-router-dom'
import StatusBadge from '../components/StatusBadge'

export default function Agents() {
  const qc = useQueryClient()
  const { data: agentList = [] } = useQuery({ queryKey: ['agents'], queryFn: agents.list, refetchInterval: 5000 })

  const [showModal, setShowModal] = useState(false)
  const [agentType, setAgentType] = useState<'server' | 'client'>('server')
  const [token, setToken] = useState<string | null>(null)

  const createToken = useMutation({
    mutationFn: () => agents.createToken(agentType),
    onSuccess: (data) => setToken(data.token),
  })

  const deleteAgent = useMutation({
    mutationFn: agents.del,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const controlUrl = window.location.origin
  const installScript = 'https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh'
  const installCmd = token
    ? `curl -fsSL ${installScript} | bash -s -- --mode ${agentType} --url ${controlUrl} --token ${token}`
    : ''

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Agents</h1>
        <button
          onClick={() => { setShowModal(true); setToken(null) }}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium"
        >
          Add Agent
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400">
              <th className="text-left px-4 py-3 font-medium">Name</th>
              <th className="text-left px-4 py-3 font-medium">Type</th>
              <th className="text-left px-4 py-3 font-medium">Hostname</th>
              <th className="text-left px-4 py-3 font-medium">Status</th>
              <th className="text-left px-4 py-3 font-medium">Version</th>
              <th className="text-left px-4 py-3 font-medium">Last Seen</th>
              <th className="text-right px-4 py-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {agentList.map((a) => (
              <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-4 py-3">
                  <Link to={`/agents/${a.id}`} className="text-blue-400 hover:underline">
                    {a.name || a.id.slice(0, 8)}
                  </Link>
                </td>
                <td className="px-4 py-3 text-gray-400">{a.type}</td>
                <td className="px-4 py-3 text-gray-400">{a.hostname || '-'}</td>
                <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                <td className="px-4 py-3 text-gray-400">{a.version || '-'}</td>
                <td className="px-4 py-3 text-gray-400">{a.last_seen ? new Date(a.last_seen).toLocaleString() : '-'}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => { if (confirm('Delete this agent?')) deleteAgent.mutate(a.id) }}
                    className="text-red-400 hover:text-red-300 text-xs"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {agentList.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No agents registered</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 w-full max-w-lg">
            <h2 className="text-lg font-bold text-white mb-4">Add Agent</h2>

            {!token ? (
              <>
                <label className="block mb-4">
                  <span className="text-sm text-gray-400">Agent Type</span>
                  <select
                    value={agentType}
                    onChange={(e) => setAgentType(e.target.value as 'server' | 'client')}
                    className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="server">Tunnel Server</option>
                    <option value="client">Tunnel Client</option>
                  </select>
                </label>
                <div className="flex gap-2 justify-end">
                  <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-gray-400 hover:text-white">Cancel</button>
                  <button
                    onClick={() => createToken.mutate()}
                    disabled={createToken.isPending}
                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium disabled:opacity-50"
                  >
                    Generate Token
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="text-sm text-gray-400 mb-2">Run this on the target machine as root (prefix with <code className="text-yellow-400">sudo</code> if not root):</p>
                <pre className="bg-gray-800 border border-gray-700 rounded p-3 text-xs text-green-400 whitespace-pre-wrap break-all select-all">
                  {installCmd}
                </pre>
                <p className="text-xs text-gray-500 mt-2">Token: <code className="text-yellow-400">{token}</code></p>
                {agentType === 'client' && (
                  <p className="text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 rounded px-3 py-2 mt-3">
                    After the agent connects, go to <strong>Tunnel Clients</strong> to select which tunnel server it should connect to and configure gateway settings.
                  </p>
                )}
                <div className="flex justify-end mt-4">
                  <button
                    onClick={() => { navigator.clipboard.writeText(installCmd); }}
                    className="mr-2 px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 text-white rounded"
                  >
                    Copy
                  </button>
                  <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-gray-400 hover:text-white">
                    Close
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
