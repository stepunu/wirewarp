import { useQuery } from '@tanstack/react-query'
import { agents, portForwards } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import { Link } from 'react-router-dom'

export default function Dashboard() {
  const { data: agentList = [] } = useQuery({ queryKey: ['agents'], queryFn: agents.list, refetchInterval: 5000 })
  const { data: pfList = [] } = useQuery({ queryKey: ['port-forwards'], queryFn: () => portForwards.list() })

  const connected = agentList.filter((a) => a.status === 'connected').length
  const disconnected = agentList.filter((a) => a.status === 'disconnected').length
  const activePF = pfList.filter((p) => p.active).length

  const cards = [
    { label: 'Total Agents', value: agentList.length, color: 'text-blue-400' },
    { label: 'Connected', value: connected, color: 'text-green-400' },
    { label: 'Disconnected', value: disconnected, color: 'text-red-400' },
    { label: 'Active Port Forwards', value: activePF, color: 'text-purple-400' },
  ]

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Dashboard</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {cards.map((c) => (
          <div key={c.label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <p className="text-sm text-gray-400">{c.label}</p>
            <p className={`text-3xl font-bold mt-1 ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      <h2 className="text-lg font-semibold text-white mb-3">Agent Status</h2>
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400">
              <th className="text-left px-4 py-3 font-medium">Name</th>
              <th className="text-left px-4 py-3 font-medium">Type</th>
              <th className="text-left px-4 py-3 font-medium">Status</th>
              <th className="text-left px-4 py-3 font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {agentList.map((a) => (
              <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-4 py-3">
                  <Link to={`/agents/${a.id}`} className="text-blue-400 hover:underline">
                    {a.name || a.hostname || a.id.slice(0, 8)}
                  </Link>
                </td>
                <td className="px-4 py-3 text-gray-400">{a.type}</td>
                <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                <td className="px-4 py-3 text-gray-400">{a.last_seen ? new Date(a.last_seen).toLocaleString() : '-'}</td>
              </tr>
            ))}
            {agentList.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-gray-500">No agents registered yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
