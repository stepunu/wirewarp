import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { nodes as nodesApi } from '../lib/api'
import { Badge, FilterBar, StatusDot, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import type { Node, NodeRole } from '../lib/types'

const ROLE_TONE: Record<NodeRole, 'info' | 'peer' | 'neutral'> = {
  server: 'info',
  gateway: 'peer',
  client: 'neutral',
}

function roleIcon(role: NodeRole) {
  if (role === 'server') return <Ic.server s={14} />
  if (role === 'gateway') return <Ic.host s={14} />
  return <Ic.client s={14} />
}

export default function Nodes() {
  const [filter, setFilter] = useState('')
  const [role, setRole] = useState<'all' | NodeRole>('all')
  const q = useQuery({ queryKey: ['nodes'], queryFn: nodesApi.list, refetchInterval: 10_000 })
  const nodes = q.data ?? []

  const filtered = useMemo(() => {
    const needle = filter.toLowerCase()
    return nodes.filter((n) => {
      if (role !== 'all' && n.role !== role) return false
      if (!needle) return true
      return [n.name, n.hostname, n.public_ip, n.agent_id]
        .filter(Boolean)
        .some((v) => v!.toLowerCase().includes(needle))
    })
  }, [filter, nodes, role])

  const gatewayCount = nodes.filter((n) => n.role === 'gateway').length
  const serverCount = nodes.filter((n) => n.role === 'server').length
  const connectedCount = nodes.filter((n) => n.status === 'connected').length

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>nodes</span>
          </div>
          <h1 className="page-title">Nodes</h1>
          <p className="page-sub mono">
            {connectedCount}/{nodes.length} connected · {serverCount} servers · {gatewayCount} gateways
          </p>
        </div>
      </div>

      <FilterBar
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'role',
            value: role,
            onChange: (v) => setRole(v as 'all' | NodeRole),
            options: [
              ['all', 'all'],
              ['server', 'server'],
              ['gateway', 'gateway'],
              ['client', 'client'],
            ],
          },
        ]}
        right={<span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>{filtered.length}/{nodes.length}</span>}
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th style={{ width: 110 }}>Role</th>
              <th>Host</th>
              <th style={{ width: 120 }}>Edge</th>
              <th style={{ width: 120 }}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className="tbl-empty">
                    <h3>{q.isLoading ? 'Loading...' : 'No nodes'}</h3>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((node) => (
              <NodeRow key={node.agent_id} node={node} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function NodeRow({ node }: { node: Node }) {
  return (
    <tr>
      <td>
        <Link to={`/nodes/${node.agent_id}`} className="row" style={{ gap: 8, color: 'inherit', textDecoration: 'none' }}>
          {roleIcon(node.role)}
          <span style={{ fontWeight: 600 }}>{node.name}</span>
          <StatusDot status={node.status} label={false} />
        </Link>
      </td>
      <td>
        <Badge tone={ROLE_TONE[node.role]}>{node.role}</Badge>
      </td>
      <td>
        <div className="mono" style={{ fontSize: 12 }}>{node.hostname || '—'}</div>
        <div className="scheme">{node.public_ip || node.agent_id.slice(0, 12)}</div>
      </td>
      <td>
        {node.role === 'server' ? (
          <Badge tone={node.edge_phase === 'healthy' ? 'ok' : node.edge_phase === 'degraded' ? 'warn' : 'neutral'}>
            {node.edge_phase || 'pending'}
          </Badge>
        ) : (
          <span className="scheme">—</span>
        )}
      </td>
      <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(node.last_seen)}</td>
    </tr>
  )
}
