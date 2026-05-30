import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  audit as auditApi,
  nodes as nodesApi,
  portForwards as pfApi,
  security as secApi,
  tunnelClientAttachments as attachApi,
  tunnelClients as tcApi,
  tunnelServers as tsApi,
} from '../lib/api'
import { Badge, Button, Dialog, Field, Input, KV, Select, Stat, StatusDot, Tabs, Toggle, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import { WgPeerTable } from '../components/WgPeerTable'
import { HealEventList } from './TunnelServerDetail'
import { CreateSiteDialog } from './SecuritySites'
import { EditProtectionDialog } from './SecurityProtections'
import { useRole } from '../hooks/useRole'
import { useToast } from '../components/Toasts'
import type {
  Node,
  NodeEdge,
  SecurityEventGroup,
  Site,
  TraefikImportPreview,
  TraefikImportRequest,
} from '../lib/types'

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
  const [showImport, setShowImport] = useState(false)
  const [editing, setEditing] = useState<Site | null>(null)
  const eventsQ = useQuery({
    queryKey: ['security-event-groups', node.agent_id],
    queryFn: () => secApi.eventGroups({ agent_id: node.agent_id, limit: 8 }),
  })
  const attachmentsQ = useQuery({
    queryKey: ['tunnel-client-attachments', 'server', node.tunnel_server_id],
    queryFn: () => attachApi.list({ tunnel_server_id: node.tunnel_server_id! }),
    enabled: !!node.tunnel_server_id && canMutate,
  })
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
      <ServerEdgeDefaults node={node} policy={edge.policy} canMutate={canMutate} />
      <div className="card">
        <div className="card-head">
          <div className="title">HTTP Sites</div>
          {canMutate && (
            <div className="row" style={{ gap: 8 }}>
              <Button size="sm" variant="ghost" leading={<Ic.download />} onClick={() => setShowImport(true)}>
                import
              </Button>
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
      <EdgeEventGroups rows={eventsQ.data ?? []} loading={eventsQ.isLoading} />
      {showCreate && (
        <CreateSiteDialog
          onClose={() => setShowCreate(false)}
          onSaved={() => qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })}
        />
      )}
      {showImport && node.tunnel_server_id && (
        <TraefikImportDialog
          serverId={node.tunnel_server_id}
          attachments={attachmentsQ.data ?? []}
          onClose={() => setShowImport(false)}
          onImported={() => {
            qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
            qc.invalidateQueries({ queryKey: ['sites'] })
          }}
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

function ServerEdgeDefaults({
  node,
  policy,
  canMutate,
}: {
  node: Node
  policy: NodeEdge['policy']
  canMutate: boolean
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [rps, setRps] = useState(policy.rate_limit_rps ? String(policy.rate_limit_rps) : '')
  const [burst, setBurst] = useState(policy.rate_limit_burst ? String(policy.rate_limit_burst) : '')
  const update = useMutation({
    mutationFn: () =>
      secApi.updateServerEdgePolicy(policy.server_id, {
        rate_limit_rps: rps ? Number(rps) : null,
        rate_limit_burst: burst ? Number(burst) : null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
      qc.invalidateQueries({ queryKey: ['server-edge-policy', policy.server_id] })
      push('edge defaults updated', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="card-head">
        <div>
          <div className="title">VPS Edge Defaults</div>
          <div className="scheme">applied before each site policy</div>
        </div>
        {canMutate && (
          <Button size="sm" variant="ghost" onClick={() => update.mutate()} disabled={update.isPending}>
            save
          </Button>
        )}
      </div>
      <div className="card-body">
        <div className="pf-attach-grid">
          <Field label="Global rate limit" hint="Requests per second across every router on this VPS">
            <Input
              type="number"
              value={rps}
              onChange={(e) => setRps(e.target.value)}
              placeholder="disabled"
              disabled={!canMutate}
              mono
            />
          </Field>
          <Field label="Global burst" hint="Blank defaults to five times the rate">
            <Input
              type="number"
              value={burst}
              onChange={(e) => setBurst(e.target.value)}
              placeholder={rps ? String(Number(rps) * 5) : 'disabled'}
              disabled={!canMutate}
              mono
            />
          </Field>
        </div>
      </div>
    </div>
  )
}

function EdgeEventGroups({ rows, loading }: { rows: SecurityEventGroup[]; loading: boolean }) {
  return (
    <div className="card" style={{ marginTop: 14 }}>
      <div className="card-head">
        <div className="title">Grouped Edge Events</div>
        <span className="scheme">recent security signals</span>
      </div>
      <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Signal</th>
              <th>IP</th>
              <th>Route</th>
              <th style={{ width: 80 }}>Count</th>
              <th style={{ width: 120 }}>Last</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className="tbl-empty">
                    <h3>{loading ? 'Loading...' : 'No grouped events'}</h3>
                  </div>
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <tr key={`${row.source}-${row.kind}-${row.ip}-${row.value}-${row.action}`}>
                <td>
                  <div className="row" style={{ gap: 6 }}>
                    <Badge tone={row.source === 'traefik' ? 'info' : row.source === 'appsec' ? 'warn' : 'err'}>
                      {row.source}
                    </Badge>
                    <span className="mono">{row.kind}</span>
                  </div>
                </td>
                <td className="mono">{row.ip || '—'}</td>
                <td className="mono">{row.value || '—'}</td>
                <td className="mono">{row.count}</td>
                <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(row.last_seen_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function TraefikImportDialog({
  serverId,
  attachments,
  onClose,
  onImported,
}: {
  serverId: string
  attachments: import('../lib/types').TunnelClientAttachment[]
  onClose: () => void
  onImported: () => void
}) {
  const push = useToast()
  const [attachmentId, setAttachmentId] = useState('')
  const [domainSuffix, setDomainSuffix] = useState('ww.step1.ro')
  const [content, setContent] = useState('')
  const [activate, setActivate] = useState(false)
  const [overwrite, setOverwrite] = useState(false)
  const [preview, setPreview] = useState<TraefikImportPreview | null>(null)
  const activeAttachment = attachmentId || attachments[0]?.id || ''

  const requestBody = (): TraefikImportRequest => ({
    server_id: serverId,
    attachment_id: activeAttachment,
    content,
    content_format: 'auto',
    domain_suffix: domainSuffix || null,
    activate,
    overwrite,
  })

  const previewImport = useMutation({
    mutationFn: () => secApi.previewTraefikImport(requestBody()),
    onSuccess: setPreview,
    onError: (e: Error) => push(e.message, 'err', 'import://'),
  })
  const applyImport = useMutation({
    mutationFn: () => secApi.importTraefik(requestBody()),
    onSuccess: (result) => {
      push(`imported ${result.created} new, updated ${result.updated}, skipped ${result.skipped}`, 'ok', 'import://')
      onImported()
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'import://'),
  })

  return (
    <Dialog
      title="Import Traefik config"
      scheme="WireWarp becomes source of truth"
      onClose={onClose}
      width={900}
      footer={
        <>
          <span className="left">
            {preview ? `${preview.summary.importable}/${preview.summary.routers} importable` : 'paste dynamic YAML or TOML'}
          </span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="ghost"
              onClick={() => previewImport.mutate()}
              disabled={previewImport.isPending || !content || !activeAttachment}
            >
              {previewImport.isPending ? 'previewing...' : 'Preview'}
            </Button>
            <Button
              variant="primary"
              onClick={() => applyImport.mutate()}
              disabled={applyImport.isPending || !preview?.summary.importable || !activeAttachment}
            >
              {applyImport.isPending ? 'importing...' : 'Import'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <div className="pf-attach-grid">
          <Field label="Attachment" hint="Gateway path these imported upstreams use">
            <Select value={activeAttachment} onChange={(e) => setAttachmentId(e.target.value)}>
              {attachments.length === 0 && <option value="">No attachments</option>}
              {attachments.map((a) => (
                <option key={a.id} value={a.id}>{a.wg_interface} ({a.tunnel_ip})</option>
              ))}
            </Select>
          </Field>
          <Field label="Template domain" hint="Replaces {{ domain }} in Ansible/Jinja templates">
            <Input value={domainSuffix} onChange={(e) => setDomainSuffix(e.target.value)} placeholder="ww.step1.ro" mono />
          </Field>
        </div>
        <div className="row" style={{ gap: 18, flexWrap: 'wrap' }}>
          <label className="row" style={{ gap: 8, fontSize: 13 }}>
            <Toggle on={activate} onChange={setActivate} />
            activate imported routes
          </label>
          <label className="row" style={{ gap: 8, fontSize: 13 }}>
            <Toggle on={overwrite} onChange={setOverwrite} />
            update existing domains
          </label>
        </div>
        <Field label="Dynamic config" hint="Paste Traefik dynamic config. You can paste external.yml and middlewares.yml together.">
          <textarea
            className="textarea input-mono"
            style={{ minHeight: 220 }}
            value={content}
            onChange={(e) => {
              setContent(e.target.value)
              setPreview(null)
            }}
            placeholder={'http:\\n  routers:\\n    jellyfin:\\n      rule: "Host(`media.{{ domain }}`)"\\n      service: jellyfin'}
          />
        </Field>
        {preview && <TraefikImportPreviewTable preview={preview} />}
      </div>
    </Dialog>
  )
}

function TraefikImportPreviewTable({ preview }: { preview: TraefikImportPreview }) {
  return (
    <div className="tbl-wrap" style={{ maxHeight: 260, overflow: 'auto' }}>
      <table className="tbl">
        <thead>
          <tr>
            <th>Router</th>
            <th>Domain</th>
            <th>Upstream</th>
            <th>Mapped</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody>
          {preview.routes.map((route) => {
            const policy = route.mapped_policy as {
              ip_allow?: unknown
              auth_mode?: unknown
              rate_limit_rps?: unknown
            }
            const mapped = [
              Array.isArray(policy.ip_allow) && policy.ip_allow.length ? 'allow' : null,
              typeof policy.auth_mode === 'string' && policy.auth_mode !== 'none' ? 'auth' : null,
              policy.rate_limit_rps ? 'rate' : null,
              route.upstream_insecure_skip_verify ? 'insecure tls' : null,
            ].filter((item): item is string => Boolean(item))
            return (
              <tr key={route.router_name} style={{ opacity: route.importable ? 1 : 0.55 }}>
                <td className="mono">{route.router_name}</td>
                <td className="mono">{route.domain || '—'}</td>
                <td className="mono">
                  {route.destination_ip ? `${route.upstream_scheme}://${route.destination_ip}:${route.destination_port}` : '—'}
                </td>
                <td>
                  <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                    {mapped.length === 0 && <span className="scheme">none</span>}
                    {mapped.map((item) => <Badge key={item} tone="info">{item}</Badge>)}
                  </div>
                </td>
                <td>
                  <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                    {route.importable && route.warnings.length === 0 && <Badge tone="ok">ready</Badge>}
                    {!route.importable && <Badge tone="err">blocked</Badge>}
                    {route.warnings.slice(0, 2).map((warning) => <Badge key={warning} tone="warn">{warning}</Badge>)}
                    {route.warnings.length > 2 && <Badge tone="neutral">+{route.warnings.length - 2}</Badge>}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
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
              s.effective_policy?.rate_limit.global ? 'global rate' : null,
              cfg?.rate_limit_rps ? 'rate' : null,
              cfg?.auth_mode && cfg.auth_mode !== 'none' ? 'auth' : null,
              cfg?.ip_allow?.length ? 'allow' : null,
              cfg?.ip_deny?.length ? 'deny' : null,
              cfg?.geo_block?.length ? 'geo' : null,
              cfg?.antibot ? 'bot' : null,
              cfg?.upstream_scheme === 'https' ? 'https upstream' : null,
            ].filter((item): item is string => Boolean(item))
            return (
              <tr key={s.id}>
                <td className="mono">{s.domain || '—'}</td>
                <td className="mono">{cfg?.upstream_scheme || 'http'}://{s.destination_ip}:{s.destination_port}</td>
                <td><Badge tone={cfg?.waf_mode === 'block' ? 'ok' : cfg?.waf_mode === 'observe' ? 'warn' : 'neutral'}>{cfg?.waf_mode || 'off'}</Badge></td>
                <td>
                  <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                    {protections.length === 0 && <span className="scheme">none</span>}
                    {protections.map((p) => <Badge key={p} tone="info">{p}</Badge>)}
                    {!!s.effective_policy?.warnings.length && <Badge tone="warn">import warnings</Badge>}
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
