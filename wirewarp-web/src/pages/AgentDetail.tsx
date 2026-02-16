import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import { agents } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: agent, isLoading } = useQuery({
    queryKey: ['agent', id],
    queryFn: () => agents.get(id!),
    refetchInterval: 5000,
  })

  const deleteAgent = useMutation({
    mutationFn: () => agents.del(id!),
    onSuccess: () => navigate('/agents'),
  })

  if (isLoading) return <p className="text-gray-400">Loading...</p>
  if (!agent) return <p className="text-red-400">Agent not found</p>

  const fields = [
    ['ID', agent.id],
    ['Name', agent.name],
    ['Type', agent.type],
    ['Hostname', agent.hostname],
    ['Public IP', agent.public_ip],
    ['Version', agent.version],
    ['Status', null],
    ['Last Seen', agent.last_seen ? new Date(agent.last_seen).toLocaleString() : '-'],
    ['Created', new Date(agent.created_at).toLocaleString()],
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">{agent.name || agent.hostname || 'Agent'}</h1>
        <button
          onClick={() => { if (confirm('Delete this agent?')) deleteAgent.mutate() }}
          className="text-red-400 hover:text-red-300 text-sm border border-red-800 px-3 py-1.5 rounded"
        >
          Delete Agent
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg">
        <dl className="divide-y divide-gray-800">
          {fields.map(([label, value]) => (
            <div key={label as string} className="flex px-4 py-3">
              <dt className="w-40 text-sm text-gray-400 shrink-0">{label}</dt>
              <dd className="text-sm text-white">
                {label === 'Status' ? <StatusBadge status={agent.status} /> : (value || '-')}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  )
}
