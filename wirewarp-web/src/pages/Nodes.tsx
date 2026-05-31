import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { agents as agentsApi, nodes as nodesApi } from '../lib/api'
import { Badge, Button, FilterBar, StatusDot, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import { useRole } from '../hooks/useRole'
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

function ComponentHealthBadges({ node }: { node: Node }) {
  const components = node.edge_components ?? {}
  const visible = ['traefik', 'crowdsec', 'appsec', 'nginx_cache']
    .map((name) => components[name])
    .filter((component): component is NonNullable<typeof component> => Boolean(component))

  if (node.role !== 'server') return <span className="scheme">—</span>
  if (visible.length === 0) return <span className="scheme">no edge components</span>

  return (
    <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
      {visible.map((component) => (
        <Badge
          key={component.component}
          tone={component.running ? 'ok' : component.desired === 'enabled' ? 'warn' : 'neutral'}
        >
          {component.component.replace('_', '-')}
        </Badge>
      ))}
    </div>
  )
}

export default function Nodes() {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [filter, setFilter] = useState('')
  const [role, setRole] = useState<'all' | NodeRole>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
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
  const allFilteredSelected = filtered.length > 0 && filtered.every((n) => selected.has(n.agent_id))
  const someFilteredSelected = filtered.some((n) => selected.has(n.agent_id))

  const updateNodes = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => agentsApi.update(id)))
      const ok = results.filter((r) => r.status === 'fulfilled').length
      return { ok, failed: results.length - ok }
    },
    onSuccess: ({ ok, failed }) => {
      const msg =
        `update dispatched to ${ok} node${ok === 1 ? '' : 's'}` +
        (failed ? ` · ${failed} offline/skipped` : '')
      push(msg, failed ? 'info' : 'ok', 'node://')
      qc.invalidateQueries({ queryKey: ['audit'] })
      setSelected(new Set())
    },
    onError: (e) => push(e instanceof Error ? e.message : 'update failed', 'err', 'node://'),
  })

  const toggleOne = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const toggleAll = () =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (allFilteredSelected) filtered.forEach((n) => next.delete(n.agent_id))
      else filtered.forEach((n) => next.add(n.agent_id))
      return next
    })
  const runUpdate = (ids: string[]) => {
    if (!ids.length) return
    if (
      confirm(
        `Update ${ids.length} node${ids.length === 1 ? '' : 's'}?\n\n` +
          'Each connected agent downloads the latest binary from main and restarts via systemd. Offline nodes are skipped.',
      )
    ) {
      updateNodes.mutate(ids)
    }
  }

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

      {canMutate && selected.size > 0 && (
        <div
          className="row"
          style={{
            gap: 12,
            alignItems: 'center',
            margin: '10px 0',
            padding: '8px 12px',
            background: 'var(--accent-bg)',
            border: '1px solid var(--accent)',
            borderRadius: 'var(--r-2)',
          }}
        >
          <span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>
            {selected.size} selected
          </span>
          <Button
            size="sm"
            variant="primary"
            leading={<Ic.download />}
            onClick={() => runUpdate([...selected])}
            disabled={updateNodes.isPending}
          >
            {updateNodes.isPending ? 'dispatching...' : `Update ${selected.size} selected`}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </div>
      )}

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              {canMutate && (
                <th style={{ width: 32 }}>
                  <input
                    type="checkbox"
                    aria-label="select all visible nodes"
                    checked={allFilteredSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = someFilteredSelected && !allFilteredSelected
                    }}
                    onChange={toggleAll}
                    style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
                  />
                </th>
              )}
              <th>Name</th>
              <th style={{ width: 110 }}>Role</th>
              <th>Host</th>
              <th style={{ width: 190 }}>Edge</th>
              <th style={{ width: 260 }}>Components</th>
              <th style={{ width: 120 }}>Last seen</th>
              {canMutate && <th style={{ width: 100 }} />}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={canMutate ? 8 : 6}>
                  <div className="tbl-empty">
                    <h3>{q.isLoading ? 'Loading...' : 'No nodes'}</h3>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((node) => (
              <NodeRow
                key={node.agent_id}
                node={node}
                canMutate={canMutate}
                selected={selected.has(node.agent_id)}
                updating={updateNodes.isPending}
                onToggle={() => toggleOne(node.agent_id)}
                onUpdate={() => runUpdate([node.agent_id])}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function NodeRow({
  node,
  canMutate,
  selected,
  updating,
  onToggle,
  onUpdate,
}: {
  node: Node
  canMutate: boolean
  selected: boolean
  updating: boolean
  onToggle: () => void
  onUpdate: () => void
}) {
  return (
    <tr>
      {canMutate && (
        <td>
          <input
            type="checkbox"
            aria-label={`select ${node.name}`}
            checked={selected}
            onChange={onToggle}
            style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
          />
        </td>
      )}
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
          <div className="col" style={{ gap: 4 }}>
            <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
              <Badge tone={node.edge_mode === 'security_edge' ? 'accent' : 'neutral'}>
                {node.edge_mode === 'security_edge' ? 'security edge' : 'tcp/udp only'}
              </Badge>
              <Badge tone={node.edge_state === 'enabled' ? 'ok' : 'neutral'}>
                {node.edge_state || 'disabled'}
              </Badge>
            </div>
            <span className="scheme">{node.edge_phase || node.edge_install_phase || 'pending'}</span>
          </div>
        ) : (
          <span className="scheme">—</span>
        )}
      </td>
      <td><ComponentHealthBadges node={node} /></td>
      <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(node.last_seen)}</td>
      {canMutate && (
        <td>
          <Button
            size="sm"
            variant="ghost"
            leading={<Ic.download />}
            onClick={onUpdate}
            disabled={updating || node.status !== 'connected'}
            title={node.status !== 'connected' ? 'node must be connected' : ''}
          >
            update
          </Button>
        </td>
      )}
    </tr>
  )
}
