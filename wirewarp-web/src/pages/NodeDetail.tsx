import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  audit as auditApi,
  nodes as nodesApi,
  portForwards as pfApi,
  tunnelClients as tcApi,
  tunnelServers as tsApi,
} from '../lib/api'
import { Badge, Button, KV, Stat, StatusDot, Tabs, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import { WgPeerTable } from '../components/WgPeerTable'
import { HealEventList } from './TunnelServerDetail'
import { CreateSiteDialog } from './SecuritySites'
import { EditProtectionDialog } from './SecurityProtections'
import { useRole } from '../hooks/useRole'
import { useToast } from '../components/Toasts'
import type { Node, NodeEdge, Site } from '../lib/types'

type Tab = 'edge' | 'forwards' | 'peers' | 'lan' | 'egress' | 'attachment' | 'activity' | 'audit'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function tabsFor(node: Node): { value: Tab; label: string; count?: number }[] {
  if (node.role === 'server') {
    return [
      { value: 'edge', label: 'Security Edge' },
      { value: 'forwards', label: 'Forwards' },
      { value: 'peers', label: 'Peers' },
      { value: 'activity', label: 'Activity' },
      { value: 'audit', label: 'Audit' },
    ]
  }
  if (node.role === 'gateway') {
    return [
      { value: 'lan', label: 'LAN' },
      { value: 'egress', label: 'Egress' },
      { value: 'activity', label: 'Activity' },
      { value: 'audit', label: 'Audit' },
    ]
  }
  return [
    { value: 'attachment', label: 'Attachment' },
    { value: 'activity', label: 'Activity' },
    { value: 'audit', label: 'Audit' },
  ]
}

export default function NodeDetail() {
  const { id } = useParams<{ id: string }>()
  const [tab, setTab] = useState<Tab>('edge')
  const nodeQ = useQuery({ queryKey: ['nodes', id], queryFn: () => nodesApi.get(id!), enabled: !!id })
  const node = nodeQ.data
  const activeTabs = useMemo(() => (node ? tabsFor(node) : []), [node])
  const activeTab: Tab = activeTabs.some((t) => t.value === tab) ? tab : (activeTabs[0]?.value ?? 'edge')

  const serverQ = useQuery({
    queryKey: ['tunnel-server-summary', node?.tunnel_server_id],
    queryFn: () => tsApi.summary(node!.tunnel_server_id!),
    enabled: !!node?.tunnel_server_id,
  })
  const clientQ = useQuery({
    queryKey: ['tunnel-client-summary', node?.tunnel_client_id],
    queryFn: () => tcApi.summary(node!.tunnel_client_id!),
    enabled: !!node?.tunnel_client_id,
  })
  const healQ = useQuery({
    queryKey: ['heal-events', id],
    queryFn: () => agentsApi.healEvents(id!, 50),
    enabled: !!id && activeTab === 'activity',
  })
  const auditQ = useQuery({
    queryKey: ['audit', id],
    queryFn: () => auditApi.list({ agent_id: id, limit: 100 }),
    enabled: !!id && activeTab === 'audit',
  })
  const edgeQ = useQuery({
    queryKey: ['node-edge', id],
    queryFn: () => nodesApi.edge(id!),
    enabled: !!id && node?.role === 'server',
  })
  const peersQ = useQuery({
    queryKey: ['wg-peers', 'node', id],
    queryFn: () =>
      node?.tunnel_server_id
        ? tsApi.wgPeers(node.tunnel_server_id)
        : tcApi.wgPeers(node!.tunnel_client_id!),
    enabled: !!node && activeTab === 'peers' && (!!node.tunnel_server_id || !!node.tunnel_client_id),
  })
  const forwardsQ = useQuery({
    queryKey: ['port-forwards', 'by-node', id],
    queryFn: () => pfApi.list({ tunnel_server_id: node!.tunnel_server_id! }),
    enabled: !!node?.tunnel_server_id && activeTab === 'forwards',
  })

  if (nodeQ.isLoading) return <div className="page"><p>Loading...</p></div>
  if (!node) return <div className="page"><h1 className="page-title">Node not found</h1></div>

  const server = serverQ.data
  const client = clientQ.data

  return (
    <div className="page">
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <Link to="/nodes" style={{ color: 'inherit', cursor: 'pointer' }}>nodes</Link>
            <span className="sep">/</span>
            <span className="here mono">{node.agent_id.slice(0, 12)}</span>
          </div>
          <h1 className="page-title">
            {node.name}
            <Badge tone={node.role === 'server' ? 'info' : node.role === 'gateway' ? 'peer' : 'neutral'}>{node.role}</Badge>
            <StatusDot status={node.status} />
          </h1>
          <p className="page-sub mono">
            {node.hostname || '—'} · {node.public_ip || 'no public ip'} · last seen {relTime(node.last_seen)}
          </p>
        </div>
      </div>

      <div className="server-stat-grid">
        <Stat label="status" value={node.status} />
        <Stat label="version" value={node.version || '—'} />
        <Stat label={node.role === 'server' ? 'edge' : 'gateway'} value={node.edge_phase || (node.is_gateway ? 'yes' : '—')} />
        <Stat label="agent" value={node.agent_id.slice(0, 8)} />
      </div>

      <Tabs<Tab> value={activeTab} onChange={setTab} tabs={activeTabs} />

      {activeTab === 'edge' && <SecurityEdgePanel node={node} edge={edgeQ.data} loading={edgeQ.isLoading} />}
      {activeTab === 'forwards' && <ForwardsTable rows={forwardsQ.data ?? []} />}
      {activeTab === 'peers' && <WgPeerTable peers={peersQ.data ?? []} />}
      {activeTab === 'lan' && <ClientPanel title="LAN" node={node} client={client} />}
      {activeTab === 'egress' && <ClientPanel title="Egress" node={node} client={client} />}
      {activeTab === 'attachment' && <ClientPanel title="Attachment" node={node} client={client} />}
      {activeTab === 'activity' && <HealEventList events={healQ.data ?? []} loading={healQ.isLoading} />}
      {activeTab === 'audit' && <AuditTable rows={auditQ.data ?? []} loading={auditQ.isLoading} />}
      {server && activeTab === 'edge' && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="card-head"><div className="title">Server WireGuard</div></div>
          <div className="card-body" style={{ padding: 0 }}>
            <KV pairs={[
              ['network', server.tunnel_network, true],
              ['interface', `${server.wg_interface}:${server.wg_port}`, true],
              ['rx', formatBytes(server.total_rx_bytes), true],
              ['tx', formatBytes(server.total_tx_bytes), true],
            ]} />
          </div>
        </div>
      )}
    </div>
  )
}

function SecurityEdgePanel({ node, edge, loading }: { node: Node; edge?: NodeEdge; loading: boolean }) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<Site | null>(null)
  const reconcile = useMutation({
    mutationFn: () => nodesApi.reconcileEdge(node.agent_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
      push('edge reconcile queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  if (loading && !edge) return <div className="card"><div className="card-body">Loading...</div></div>
  if (!edge) return null

  return (
    <>
      <div className="server-stat-grid">
        <Stat label="edge phase" value={edge.phase} />
        <Stat label="crowdsec" value={edge.crowdsec.running ? 'running' : edge.crowdsec.phase} />
        <Stat label="traefik" value={edge.traefik.running ? 'running' : edge.traefik.phase} />
        <Stat label="sites" value={String(edge.sites.length)} />
      </div>
      <div className="card">
        <div className="card-head">
          <div className="title">HTTP Sites</div>
          {canMutate && (
            <div className="row" style={{ gap: 8 }}>
              <Button size="sm" variant="ghost" leading={<Ic.plus />} onClick={() => setShowCreate(true)}>
                add site
              </Button>
              <Button size="sm" variant="ghost" leading={<Ic.refresh />} onClick={() => reconcile.mutate()} disabled={reconcile.isPending}>
                reconcile
              </Button>
            </div>
          )}
        </div>
        <SitesTable sites={edge.sites} canMutate={canMutate} onEdit={setEditing} />
      </div>
      {showCreate && (
        <CreateSiteDialog
          onClose={() => setShowCreate(false)}
          onSaved={() => qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })}
        />
      )}
      {editing && (
        <EditProtectionDialog
          site={editing}
          onClose={() => setEditing(null)}
          onSaved={() => qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })}
        />
      )}
    </>
  )
}

function SitesTable({
  sites,
  canMutate,
  onEdit,
}: {
  sites: Site[]
  canMutate: boolean
  onEdit: (site: Site) => void
}) {
  return (
    <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
      <table className="tbl">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Upstream</th>
            <th>WAF</th>
            <th>Protections</th>
            <th>State</th>
            {canMutate && <th style={{ width: 90 }} />}
          </tr>
        </thead>
        <tbody>
          {sites.length === 0 && (
            <tr><td colSpan={canMutate ? 6 : 5}><div className="tbl-empty"><h3>No sites</h3></div></td></tr>
          )}
          {sites.map((s) => {
            const cfg = s.edge_config
            const protections = [
              cfg?.rate_limit_rps ? 'rate' : null,
              cfg?.auth_mode && cfg.auth_mode !== 'none' ? 'auth' : null,
              cfg?.ip_allow?.length ? 'allow' : null,
              cfg?.ip_deny?.length ? 'deny' : null,
              cfg?.geo_block?.length ? 'geo' : null,
              cfg?.antibot ? 'bot' : null,
            ].filter(Boolean)
            return (
              <tr key={s.id}>
                <td className="mono">{s.domain || '—'}</td>
                <td className="mono">{s.destination_ip}:{s.destination_port}</td>
                <td><Badge tone={cfg?.waf_mode === 'block' ? 'ok' : cfg?.waf_mode === 'observe' ? 'warn' : 'neutral'}>{cfg?.waf_mode || 'off'}</Badge></td>
                <td>
                  <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                    {protections.length === 0 && <span className="scheme">none</span>}
                    {protections.map((p) => <Badge key={p} tone="info">{p}</Badge>)}
                  </div>
                </td>
                <td><Badge tone={s.active ? 'ok' : 'neutral'}>{s.active ? 'active' : 'off'}</Badge></td>
                {canMutate && (
                  <td>
                    <Button size="sm" variant="ghost" onClick={() => onEdit(s)}>
                      edit
                    </Button>
                  </td>
                )}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ClientPanel({ title, node, client }: { title: string; node: Node; client?: import('../lib/types').TunnelClientSummary }) {
  return (
    <div className="card">
      <div className="card-head"><div className="title">{title}</div></div>
      <div className="card-body" style={{ padding: 0 }}>
        <KV pairs={[
          ['client id', node.tunnel_client_id || '—', true],
          ['lan ip', client?.lan_ip || '—', true],
          ['vm network', client?.vm_network || '—', true],
          ['attachments', String(client?.attachments.length ?? 0), true],
          ['rx', formatBytes(client?.total_rx_bytes ?? 0), true],
          ['tx', formatBytes(client?.total_tx_bytes ?? 0), true],
        ]} />
      </div>
    </div>
  )
}

function ForwardsTable({ rows }: { rows: import('../lib/types').PortForward[] }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead><tr><th>Proto</th><th>Public</th><th>Destination</th><th>Description</th><th>State</th></tr></thead>
        <tbody>
          {rows.length === 0 && <tr><td colSpan={5}><div className="tbl-empty"><h3>No forwards</h3></div></td></tr>}
          {rows.map((p) => (
            <tr key={p.id}>
              <td><Badge tone={p.protocol === 'tcp' ? 'info' : 'peer'}>{p.protocol}</Badge></td>
              <td className="mono">:{p.public_port_end ? `${p.public_port}-${p.public_port_end}` : p.public_port}</td>
              <td className="mono">{p.destination_ip}:{p.destination_port_end ? `${p.destination_port}-${p.destination_port_end}` : p.destination_port}</td>
              <td>{p.description || '—'}</td>
              <td><Badge tone={p.active ? 'ok' : 'neutral'}>{p.active ? 'active' : 'off'}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AuditTable({ rows, loading }: { rows: import('../lib/types').AuditEntry[]; loading: boolean }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead><tr><th>When</th><th>Command</th><th>Actor</th><th>Result</th></tr></thead>
        <tbody>
          {rows.length === 0 && <tr><td colSpan={4}><div className="tbl-empty"><h3>{loading ? 'Loading...' : 'No audit rows'}</h3></div></td></tr>}
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="mono">{relTime(r.executed_at)}</td>
              <td className="mono">{r.command_type}</td>
              <td>{r.actor_username || 'system'}</td>
              <td><Badge tone={r.success == null ? 'neutral' : r.success ? 'ok' : 'err'}>{r.success == null ? 'pending' : r.success ? 'ok' : 'failed'}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
