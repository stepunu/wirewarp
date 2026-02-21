import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import { agents } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [jwtModal, setJwtModal] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: agent, isLoading } = useQuery({
    queryKey: ['agent', id],
    queryFn: () => agents.get(id!),
    refetchInterval: 5000,
  })

  const deleteAgent = useMutation({
    mutationFn: () => agents.del(id!),
    onSuccess: () => navigate('/agents'),
  })

  const issueJwt = useMutation({
    mutationFn: () => agents.issueJwt(id!),
    onSuccess: (data) => {
      setJwtModal(data.jwt)
      setCopied(false)
    },
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

  const sedCommand = jwtModal
    ? `sudo sed -i "s|^agent_jwt:.*|agent_jwt: ${jwtModal}|" /etc/wirewarp/agent.yaml\nsudo systemctl restart wirewarp-agent`
    : ''

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">{agent.name || agent.hostname || 'Agent'}</h1>
        <div className="flex gap-2">
          <button
            onClick={() => issueJwt.mutate()}
            disabled={issueJwt.isPending}
            className="text-blue-400 hover:text-blue-300 text-sm border border-blue-800 px-3 py-1.5 rounded disabled:opacity-50"
          >
            {issueJwt.isPending ? 'Issuing…' : 'Reissue JWT'}
          </button>
          <button
            onClick={() => { if (confirm('Delete this agent?')) deleteAgent.mutate() }}
            className="text-red-400 hover:text-red-300 text-sm border border-red-800 px-3 py-1.5 rounded"
          >
            Delete Agent
          </button>
        </div>
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

      {jwtModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-lg w-full max-w-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">New Agent JWT</h2>
              <button onClick={() => setJwtModal(null)} className="text-gray-400 hover:text-white text-xl leading-none">&times;</button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <p className="text-sm text-gray-400">
                Copy this JWT and apply it on the agent machine. The agent will reconnect without losing any configuration or WireGuard state.
              </p>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-500 uppercase tracking-wide">JWT Token</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(jwtModal)
                      setCopied(true)
                      setTimeout(() => setCopied(false), 2000)
                    }}
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <pre className="bg-gray-950 border border-gray-800 rounded p-3 text-xs text-green-400 break-all whitespace-pre-wrap font-mono">
                  {jwtModal}
                </pre>
              </div>

              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wide block mb-1">Apply on agent machine</span>
                <pre className="bg-gray-950 border border-gray-800 rounded p-3 text-xs text-yellow-300 whitespace-pre font-mono select-all">
                  {sedCommand}
                </pre>
              </div>
            </div>
            <div className="px-5 py-4 border-t border-gray-800 flex justify-end">
              <button
                onClick={() => setJwtModal(null)}
                className="text-sm text-gray-300 hover:text-white border border-gray-700 px-4 py-1.5 rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
