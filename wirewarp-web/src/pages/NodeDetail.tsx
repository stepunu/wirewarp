import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  audit as auditApi,
  edge as edgeApi,
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
  EdgeAccessEvent,
  EdgeCacheState,
  EdgeConfigVersion,
  EdgeFragment,
  EdgeNodePolicy,
  EdgeProfile,
  EdgeRoute,
  SecurityEventGroup,
  Site,
  TraefikImportPreview,
  TraefikImportRequest,
  WafMode,
} from '../lib/types'

type Tab =
  | 'overview'
  | 'routes'
  | 'security'
  | 'rate'
  | 'access'
  | 'tls'
  | 'origin'
  | 'headers'
  | 'cache'
  | 'import'
  | 'advanced'
  | 'forwards'
  | 'peers'
  | 'lan'
  | 'egress'
  | 'attachment'
  | 'activity'
  | 'audit'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function tabsFor(node: Node): { value: Tab; label: string; count?: number }[] {
  if (node.role === 'server') {
    return [
      { value: 'overview', label: 'Overview' },
      { value: 'routes', label: 'Routes' },
      { value: 'security', label: 'Security' },
      { value: 'rate', label: 'Rate Limits' },
      { value: 'access', label: 'Access' },
      { value: 'tls', label: 'TLS' },
      { value: 'origin', label: 'Origin' },
      { value: 'headers', label: 'Headers & Transforms' },
      { value: 'cache', label: 'Cache' },
      { value: 'import', label: 'Import/Diff' },
      { value: 'advanced', label: 'Advanced' },
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
  const [tab, setTab] = useState<Tab>('overview')
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
  const edgeActive = edgeQ.data?.mode === 'security_edge' && edgeQ.data.state === 'enabled'
  const routeTabs: Tab[] = ['routes', 'security', 'rate', 'tls', 'origin', 'headers', 'cache', 'import', 'advanced']
  const routesQ = useQuery({
    queryKey: ['edge-routes', id],
    queryFn: () => nodesApi.edgeRoutes(id!),
    enabled: !!id && node?.role === 'server' && edgeActive && routeTabs.includes(activeTab),
  })
  const profilesQ = useQuery({
    queryKey: ['edge-profiles'],
    queryFn: edgeApi.profiles,
    enabled: node?.role === 'server' && edgeActive && ['routes', 'security', 'rate', 'tls', 'origin', 'headers', 'advanced'].includes(activeTab),
  })
  const policyQ = useQuery({
    queryKey: ['edge-policy', id],
    queryFn: () => nodesApi.edgePolicy(id!),
    enabled: !!id && node?.role === 'server' && edgeActive && ['overview', 'rate', 'advanced'].includes(activeTab),
  })
  const accessQ = useQuery({
    queryKey: ['node-edge-access', id],
    queryFn: () => nodesApi.edgeAccessEvents(id!, { limit: 100 }),
    enabled: !!id && node?.role === 'server' && edgeActive && activeTab === 'access',
  })
  const cacheQ = useQuery({
    queryKey: ['edge-cache', id],
    queryFn: () => nodesApi.edgeCache(id!),
    enabled: !!id && node?.role === 'server' && activeTab === 'cache',
  })
  const renderedQ = useQuery({
    queryKey: ['edge-rendered', id],
    queryFn: () => nodesApi.edgeRendered(id!),
    enabled: !!id && node?.role === 'server' && edgeActive && ['import', 'advanced'].includes(activeTab),
  })
  const versionsQ = useQuery({
    queryKey: ['edge-versions', id],
    queryFn: () => nodesApi.edgeVersions(id!),
    enabled: !!id && node?.role === 'server' && edgeActive && ['import', 'advanced'].includes(activeTab),
  })
  const fragmentsQ = useQuery({
    queryKey: ['edge-fragments', id],
    queryFn: () => nodesApi.edgeFragments(id!),
    enabled: !!id && node?.role === 'server' && edgeActive && activeTab === 'advanced',
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
          <p className="page-sub mono" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span>{node.hostname || '—'}</span>
            <span>·</span>
            <span>{node.public_ip || 'no public ip'}</span>
            <span>·</span>
            <span>last seen {relTime(node.last_seen)}</span>
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

      {activeTab === 'overview' && <EdgeOverviewPanel node={node} edge={edgeQ.data} policy={policyQ.data} loading={edgeQ.isLoading} />}
      {node.role === 'server' && routeTabs.includes(activeTab) && !edgeActive && (
        <EdgeEnablePanel node={node} edge={edgeQ.data} loading={edgeQ.isLoading} />
      )}
      {activeTab === 'routes' && edgeActive && (
        <EdgeRoutesPanel
          node={node}
          routes={routesQ.data ?? []}
          profiles={profilesQ.data ?? []}
          loading={routesQ.isLoading}
        />
      )}
      {activeTab === 'security' && edgeActive && (
        <SecurityEdgePanel node={node} edge={edgeQ.data} routes={routesQ.data ?? []} loading={edgeQ.isLoading || routesQ.isLoading} />
      )}
      {activeTab === 'rate' && edgeActive && (
        <EdgeRateLimitsPanel node={node} edge={edgeQ.data} policy={policyQ.data} routes={routesQ.data ?? []} />
      )}
      {activeTab === 'access' && edgeActive && (
        <EdgeAccessPanel node={node} events={accessQ.data?.items ?? []} loading={accessQ.isLoading} />
      )}
      {activeTab === 'tls' && edgeActive && <EdgeRoutePolicyPanel title="TLS" routes={routesQ.data ?? []} kind="tls" />}
      {activeTab === 'origin' && edgeActive && <EdgeRoutePolicyPanel title="Origin" routes={routesQ.data ?? []} kind="origin" />}
      {activeTab === 'headers' && edgeActive && <EdgeRoutePolicyPanel title="Headers & Transforms" routes={routesQ.data ?? []} kind="headers" />}
      {activeTab === 'cache' && edgeActive && (
        <EdgeCachePanel node={node} cache={cacheQ.data} routes={routesQ.data ?? []} loading={cacheQ.isLoading} />
      )}
      {activeTab === 'import' && edgeActive && (
        <EdgeImportDiffPanel
          node={node}
          rendered={renderedQ.data}
          versions={versionsQ.data ?? []}
          loading={renderedQ.isLoading || versionsQ.isLoading}
        />
      )}
      {activeTab === 'advanced' && edgeActive && (
        <EdgeAdvancedPanel
          node={node}
          edge={edgeQ.data}
          policy={policyQ.data}
          rendered={renderedQ.data}
          versions={versionsQ.data ?? []}
          fragments={fragmentsQ.data ?? []}
        />
      )}
      {activeTab === 'forwards' && <ForwardsTable rows={forwardsQ.data ?? []} />}
      {activeTab === 'peers' && <WgPeerTable peers={peersQ.data ?? []} />}
      {activeTab === 'lan' && <ClientPanel title="LAN" node={node} client={client} />}
      {activeTab === 'egress' && <ClientPanel title="Egress" node={node} client={client} />}
      {activeTab === 'attachment' && <ClientPanel title="Attachment" node={node} client={client} />}
      {activeTab === 'activity' && <HealEventList events={healQ.data ?? []} loading={healQ.isLoading} />}
      {activeTab === 'audit' && <AuditTable rows={auditQ.data ?? []} loading={auditQ.isLoading} />}
      {server && activeTab === 'overview' && (
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

function isEdgeActive(edge?: NodeEdge): boolean {
  return edge?.mode === 'security_edge' && edge.state === 'enabled'
}

function phaseTone(phase?: string | null): 'neutral' | 'ok' | 'warn' | 'err' | 'info' {
  if (phase === 'healthy' || phase === 'enabled') return 'ok'
  if (phase === 'degraded' || phase === 'pending') return 'warn'
  if (phase === 'disabled') return 'neutral'
  if (phase === 'error') return 'err'
  return 'neutral'
}

function componentName(name: string): string {
  return name.replace(/_/g, '-')
}

function EdgeLifecycleActions({ node, edge }: { node: Node; edge?: NodeEdge }) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['nodes'] })
    qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
    qc.invalidateQueries({ queryKey: ['edge-capabilities', node.agent_id] })
  }
  const install = useMutation({
    mutationFn: () => nodesApi.installEdge(node.agent_id),
    onSuccess: () => {
      invalidate()
      push('edge install queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })
  const enable = useMutation({
    mutationFn: () => nodesApi.enableEdge(node.agent_id),
    onSuccess: () => {
      invalidate()
      push('edge enable queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })
  const disable = useMutation({
    mutationFn: () => nodesApi.disableEdge(node.agent_id),
    onSuccess: () => {
      invalidate()
      push('edge disable queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })
  const reconcile = useMutation({
    mutationFn: () => nodesApi.reconcileEdge(node.agent_id),
    onSuccess: () => {
      invalidate()
      push('edge reconcile queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })
  const pending = install.isPending || enable.isPending || disable.isPending || reconcile.isPending
  const active = isEdgeActive(edge)

  if (!canMutate) return null
  return (
    <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Button size="sm" variant="primary" leading={<Ic.download />} onClick={() => install.mutate()} disabled={pending}>
        install
      </Button>
      <Button size="sm" variant="ghost" leading={<Ic.play />} onClick={() => enable.mutate()} disabled={pending || active}>
        enable
      </Button>
      <Button size="sm" variant="ghost" leading={<Ic.refresh />} onClick={() => reconcile.mutate()} disabled={pending || !active}>
        reconcile
      </Button>
      <Button size="sm" variant="danger" onClick={() => disable.mutate()} disabled={pending || !active}>
        disable
      </Button>
    </div>
  )
}

function EdgeOverviewPanel({
  node,
  edge,
  policy,
  loading,
}: {
  node: Node
  edge?: NodeEdge
  policy?: EdgeNodePolicy
  loading: boolean
}) {
  if (loading && !edge) return <div className="card"><div className="card-body">Loading...</div></div>
  if (!edge) return null
  const components = Object.values(edge.components)

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Node Edge</div>
            <div className="scheme">{edge.mode === 'security_edge' ? 'security edge' : 'tcp/udp forwarding only'}</div>
          </div>
          <EdgeLifecycleActions node={node} edge={edge} />
        </div>
        <div className="card-body">
          <div className="server-stat-grid" style={{ padding: 0, border: 0, marginBottom: 12 }}>
            <Stat label="mode" value={edge.mode === 'security_edge' ? 'security edge' : 'tcp/udp only'} />
            <Stat label="state" value={edge.state} />
            <Stat label="phase" value={edge.phase} />
            <Stat label="install" value={edge.install_phase} />
          </div>
          {edge.unavailable_reason && (
            <div className="scheme">
              HTTP edge controls are paused: {edge.unavailable_reason}.
            </div>
          )}
        </div>
      </div>
      {!isEdgeActive(edge) && <EdgeEnablePanel node={node} edge={edge} loading={false} />}
      <div className="card">
        <div className="card-head">
          <div className="title">Component Health</div>
          <span className="scheme">{components.filter((c) => c.running).length}/{components.length} running</span>
        </div>
        <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
          <table className="tbl">
            <thead><tr><th>Component</th><th>Desired</th><th>Runtime</th><th>Version</th><th>Error</th></tr></thead>
            <tbody>
              {components.map((component) => (
                <tr key={component.component}>
                  <td data-label="Component" className="mono">{componentName(component.component)}</td>
                  <td data-label="Desired"><Badge tone={component.desired === 'enabled' ? 'ok' : 'neutral'}>{component.desired}</Badge></td>
                  <td data-label="Runtime">
                    <Badge tone={component.running ? 'ok' : phaseTone(component.phase)}>
                      {component.running ? 'running' : component.phase}
                    </Badge>
                  </td>
                  <td data-label="Version" className="mono">{component.version || '—'}</td>
                  <td data-label="Error" className="mono" style={{ color: 'var(--fg-2)' }}>{component.last_error || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {policy && (
        <div className="card">
          <div className="card-head"><div className="title">Policy Defaults</div></div>
          <div className="card-body" style={{ padding: 0 }}>
            <KV pairs={[
              ['profile', policy.default_profile_id || '—', true],
              ['client ip', policy.client_ip_strategy, true],
              ['cloudflare', policy.cloudflare_mode, true],
              ['access log', `${policy.access_log_retention_hours}h`, true],
            ]} />
          </div>
        </div>
      )}
    </div>
  )
}

function EdgeEnablePanel({ node, edge, loading }: { node: Node; edge?: NodeEdge; loading: boolean }) {
  if (loading && !edge) return <div className="card"><div className="card-body">Loading...</div></div>
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="title">Enable Security Edge</div>
          <div className="scheme">keeps raw TCP/UDP forwards separate</div>
        </div>
        <EdgeLifecycleActions node={node} edge={edge} />
      </div>
      <div className="card-body">
        <div className="gridcols-3">
          <Stat label="current mode" value={edge?.mode === 'security_edge' ? 'security edge' : 'tcp/udp only'} />
          <Stat label="state" value={edge?.state || 'disabled'} />
          <Stat label="saved config" value={edge?.install_phase === 'disabled' ? 'preserved' : edge?.install_phase || 'pending'} />
        </div>
      </div>
    </div>
  )
}

function policyLabel(policy: Record<string, unknown> | null | undefined, key: string, fallback = 'inherit'): string {
  const value = policy?.[key]
  if (value == null || value === '') return fallback
  if (Array.isArray(value)) return value.length ? value.join(', ') : fallback
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function profileLabel(profiles: EdgeProfile[], id: string | null): string {
  if (!id) return 'inherit'
  return profiles.find((profile) => profile.id === id)?.slug || id.slice(0, 8)
}

function EdgeRoutesPanel({
  node,
  routes,
  profiles,
  loading,
}: {
  node: Node
  routes: EdgeRoute[]
  profiles: EdgeProfile[]
  loading: boolean
}) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [showCreate, setShowCreate] = useState(false)
  const toggle = useMutation({
    mutationFn: (route: EdgeRoute) => edgeApi.updateRoute(route.id, { enabled: !route.enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['edge-routes', node.agent_id] })
      qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
      push('route updated', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="title">HTTP Routes</div>
          <div className="scheme">domain keyed route policy</div>
        </div>
        {canMutate && (
          <Button size="sm" variant="ghost" leading={<Ic.plus />} onClick={() => setShowCreate(true)}>
            add route
          </Button>
        )}
      </div>
      <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Upstream</th>
              <th>Profile</th>
              <th>WAF</th>
              <th>Rate</th>
              <th>State</th>
              {canMutate && <th style={{ width: 90 }} />}
            </tr>
          </thead>
          <tbody>
            {routes.length === 0 && (
              <tr>
                <td colSpan={canMutate ? 7 : 6}>
                  <div className="tbl-empty"><h3>{loading ? 'Loading...' : 'No routes'}</h3></div>
                </td>
              </tr>
            )}
            {routes.map((route) => (
              <tr key={route.id}>
                <td className="mono">{route.domain || '—'}</td>
                <td className="mono">{route.destination_ip}:{route.destination_port}</td>
                <td className="mono">{profileLabel(profiles, route.profile_id)}</td>
                <td><Badge tone={policyLabel(route.effective, 'waf_mode') === 'block' ? 'ok' : 'neutral'}>{policyLabel(route.effective, 'waf_mode')}</Badge></td>
                <td className="mono">{policyLabel(route.effective, 'rate_limit_rps', 'inherit')}</td>
                <td><Badge tone={route.enabled ? 'ok' : 'neutral'}>{route.enabled ? 'active' : 'off'}</Badge></td>
                {canMutate && (
                  <td>
                    <Button size="sm" variant="ghost" onClick={() => toggle.mutate(route)} disabled={toggle.isPending}>
                      {route.enabled ? 'disable' : 'enable'}
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showCreate && (
        <RouteUpsertDialog
          node={node}
          profiles={profiles}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            qc.invalidateQueries({ queryKey: ['edge-routes', node.agent_id] })
            qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
            setShowCreate(false)
          }}
        />
      )}
    </div>
  )
}

function RouteUpsertDialog({
  node,
  profiles,
  onClose,
  onSaved,
}: {
  node: Node
  profiles: EdgeProfile[]
  onClose: () => void
  onSaved: () => void
}) {
  const push = useToast()
  const [domain, setDomain] = useState('')
  const [attachmentId, setAttachmentId] = useState('')
  const [destinationIp, setDestinationIp] = useState('')
  const [destinationPort, setDestinationPort] = useState('8080')
  const [profileId, setProfileId] = useState('')
  const [wafMode, setWafMode] = useState<WafMode>('observe')
  const attachmentsQ = useQuery({
    queryKey: ['tunnel-client-attachments', 'server', node.tunnel_server_id],
    queryFn: () => attachApi.list({ tunnel_server_id: node.tunnel_server_id! }),
    enabled: !!node.tunnel_server_id,
  })
  const activeAttachment = attachmentId || attachmentsQ.data?.[0]?.id || ''
  const save = useMutation({
    mutationFn: () =>
      nodesApi.upsertEdgeRouteByDomain(node.agent_id, domain, {
        attachment_id: activeAttachment,
        enabled: true,
        destination_ip: destinationIp,
        destination_port: Number(destinationPort),
        profile_id: profileId || null,
        upstream_scheme: 'http',
        policy: { waf_mode: wafMode },
      }),
    onSuccess: () => {
      push('route saved', 'ok', 'edge://')
      onSaved()
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <Dialog
      title="Add route"
      scheme="PUT /api/nodes/{node}/edge/routes/by-domain/{domain}"
      onClose={onClose}
      footer={
        <>
          <span className="left">{activeAttachment ? 'ready' : 'select an attachment'}</span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              onClick={() => save.mutate()}
              disabled={save.isPending || !domain || !activeAttachment || !destinationIp || !destinationPort}
            >
              {save.isPending ? 'saving...' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <div className="pf-attach-grid">
          <Field label="Domain">
            <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="app.example.com" mono />
          </Field>
          <Field label="Attachment">
            <Select value={activeAttachment} onChange={(e) => setAttachmentId(e.target.value)}>
              {attachmentsQ.data?.length ? null : <option value="">No attachments</option>}
              {(attachmentsQ.data ?? []).map((attachment) => (
                <option key={attachment.id} value={attachment.id}>{attachment.wg_interface} ({attachment.tunnel_ip})</option>
              ))}
            </Select>
          </Field>
        </div>
        <div className="pf-attach-grid">
          <Field label="Origin IP">
            <Input value={destinationIp} onChange={(e) => setDestinationIp(e.target.value)} placeholder="192.168.1.10" mono />
          </Field>
          <Field label="Origin port">
            <Input type="number" value={destinationPort} onChange={(e) => setDestinationPort(e.target.value)} mono />
          </Field>
        </div>
        <div className="pf-attach-grid">
          <Field label="Profile">
            <Select value={profileId} onChange={(e) => setProfileId(e.target.value)}>
              <option value="">inherit</option>
              {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.slug}</option>)}
            </Select>
          </Field>
          <Field label="WAF mode">
            <Select value={wafMode} onChange={(e) => setWafMode(e.target.value as WafMode)}>
              <option value="off">off</option>
              <option value="observe">observe</option>
              <option value="block">block</option>
            </Select>
          </Field>
        </div>
      </div>
    </Dialog>
  )
}

function SecurityEdgePanel({
  node,
  edge,
  routes,
  loading,
}: {
  node: Node
  edge?: NodeEdge
  routes: EdgeRoute[]
  loading: boolean
}) {
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
        <Stat label="routes" value={`${routes.length || edge.sites.length}`} />
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
          agentId={node.agent_id}
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

function EdgeRateLimitsPanel({
  node,
  edge,
  policy,
  routes,
}: {
  node: Node
  edge?: NodeEdge
  policy?: EdgeNodePolicy
  routes: EdgeRoute[]
}) {
  const { canMutate } = useRole()
  if (!edge) return null
  return (
    <div className="col" style={{ gap: 14 }}>
      <ServerEdgeDefaults node={node} policy={edge.policy} canMutate={canMutate} />
      <div className="card">
        <div className="card-head">
          <div className="title">Route Rate Limits</div>
          <span className="scheme">{policy?.client_ip_strategy || 'xff'} client IP strategy</span>
        </div>
        <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
          <table className="tbl">
            <thead><tr><th>Route</th><th>Effective RPS</th><th>Burst</th><th>Profile</th></tr></thead>
            <tbody>
              {routes.length === 0 && <tr><td colSpan={4}><div className="tbl-empty"><h3>No routes</h3></div></td></tr>}
              {routes.map((route) => (
                <tr key={route.id}>
                  <td className="mono">{route.domain || route.id.slice(0, 8)}</td>
                  <td className="mono">{policyLabel(route.effective, 'rate_limit_rps')}</td>
                  <td className="mono">{policyLabel(route.effective, 'rate_limit_burst')}</td>
                  <td className="mono">{route.profile_id?.slice(0, 8) || 'inherit'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function EdgeAccessPanel({
  events,
  loading,
}: {
  node: Node
  events: EdgeAccessEvent[]
  loading: boolean
}) {
  const [host, setHost] = useState('')
  const [path, setPath] = useState('')
  const [status, setStatus] = useState('')
  const [action, setAction] = useState('')
  const [ip, setIp] = useState('')
  const [country, setCountry] = useState('')
  const [method, setMethod] = useState('')
  const [since, setSince] = useState('24h')
  const filtered = useMemo(() => {
    const sinceMs =
      since === '1h' ? 60 * 60 * 1000 :
      since === '7d' ? 7 * 24 * 60 * 60 * 1000 :
      since === '30d' ? 30 * 24 * 60 * 60 * 1000 :
      24 * 60 * 60 * 1000
    const cutoff = Date.now() - sinceMs
    return events.filter((event) => {
      if (host && !event.host?.includes(host)) return false
      if (path && !event.path?.startsWith(path)) return false
      if (status && String(event.status_code || '') !== status) return false
      if (action && event.action !== action) return false
      if (ip && !event.client_ip?.includes(ip)) return false
      if (country && event.client_country !== country.toUpperCase()) return false
      if (method && event.method !== method.toUpperCase()) return false
      return new Date(event.occurred_at).getTime() >= cutoff
    })
  }, [action, country, events, host, ip, method, path, since, status])

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="title">Live Access Feed</div>
          <div className="scheme">Traefik JSON access events</div>
        </div>
        <Badge tone="info">{filtered.length}/{events.length}</Badge>
      </div>
      <div className="card-body">
        <div className="gridcols-4">
          <Field label="Host"><Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" mono /></Field>
          <Field label="Path"><Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/api" mono /></Field>
          <Field label="Status"><Input value={status} onChange={(e) => setStatus(e.target.value)} placeholder="403" mono /></Field>
          <Field label="Action"><Input value={action} onChange={(e) => setAction(e.target.value)} placeholder="block" mono /></Field>
          <Field label="IP"><Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="198.51.100" mono /></Field>
          <Field label="Country"><Input value={country} onChange={(e) => setCountry(e.target.value)} placeholder="US" mono /></Field>
          <Field label="Method"><Input value={method} onChange={(e) => setMethod(e.target.value)} placeholder="GET" mono /></Field>
          <Field label="Range">
            <Select value={since} onChange={(e) => setSince(e.target.value)}>
              <option value="1h">1h</option>
              <option value="24h">24h</option>
              <option value="7d">7d</option>
              <option value="30d">30d</option>
            </Select>
          </Field>
        </div>
      </div>
      <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
        <table className="tbl">
          <thead><tr><th>When</th><th>Host</th><th>Request</th><th>Status</th><th>Action</th><th>Client</th><th>Cache</th><th>Latency</th></tr></thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={8}><div className="tbl-empty"><h3>{loading ? 'Loading...' : 'No access events'}</h3></div></td></tr>
            )}
            {filtered.map((event) => (
              <tr key={event.id}>
                <td className="mono">{relTime(event.occurred_at)}</td>
                <td className="mono">{event.host || '—'}</td>
                <td className="mono">{event.method || '—'} {event.path || '/'}</td>
                <td><Badge tone={(event.status_code || 0) >= 500 ? 'err' : (event.status_code || 0) >= 400 ? 'warn' : 'ok'}>{event.status_code || '—'}</Badge></td>
                <td><Badge tone={event.action === 'block' ? 'err' : event.action === 'challenge' ? 'warn' : 'neutral'}>{event.action}</Badge></td>
                <td className="mono">{event.client_ip || '—'}{event.client_country ? ` · ${event.client_country}` : ''}</td>
                <td className="mono">{event.cache_status || '—'}</td>
                <td className="mono">{event.latency_ms != null ? `${event.latency_ms}ms` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function EdgeRoutePolicyPanel({ title, routes, kind }: { title: string; routes: EdgeRoute[]; kind: 'tls' | 'origin' | 'headers' }) {
  const columns =
    kind === 'tls'
      ? ['tls_source', 'redirect_https', 'hsts']
      : kind === 'origin'
        ? ['upstream_scheme', 'upstream_timeout', 'retry_attempts']
        : ['headers', 'request_transforms', 'response_transforms']
  return (
    <div className="card">
      <div className="card-head">
        <div className="title">{title}</div>
        <span className="scheme">effective route policy</span>
      </div>
      <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
        <table className="tbl">
          <thead><tr><th>Route</th>{columns.map((column) => <th key={column}>{column.replace(/_/g, ' ')}</th>)}</tr></thead>
          <tbody>
            {routes.length === 0 && <tr><td colSpan={columns.length + 1}><div className="tbl-empty"><h3>No routes</h3></div></td></tr>}
            {routes.map((route) => (
              <tr key={route.id}>
                <td className="mono">{route.domain || route.id.slice(0, 8)}</td>
                {columns.map((column) => <td key={column} className="mono">{policyLabel(route.effective, column)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function EdgeCachePanel({
  node,
  cache,
  routes,
  loading,
}: {
  node: Node
  cache?: EdgeCacheState
  routes: EdgeRoute[]
  loading: boolean
}) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const invalidate = () => qc.invalidateQueries({ queryKey: ['edge-cache', node.agent_id] })
  const mode = typeof cache?.policy.mode === 'string' ? cache.policy.mode : 'off'
  const update = useMutation({
    mutationFn: (nextMode: string) => nodesApi.updateEdgeCache(node.agent_id, { mode: nextMode, cache_status_header: true }),
    onSuccess: () => {
      invalidate()
      push('cache policy updated', 'ok', 'cache://')
    },
    onError: (e: Error) => push(e.message, 'err', 'cache://'),
  })
  const install = useMutation({
    mutationFn: () => nodesApi.installEdgeCache(node.agent_id),
    onSuccess: () => {
      invalidate()
      push('cache reconcile queued', 'ok', 'cache://')
    },
    onError: (e: Error) => push(e.message, 'err', 'cache://'),
  })
  const test = useMutation({
    mutationFn: () => nodesApi.testEdgeCache(node.agent_id),
    onSuccess: (result) => push(`cache test ${result.status}`, 'ok', 'cache://'),
    onError: (e: Error) => push(e.message, 'err', 'cache://'),
  })
  const purge = useMutation({
    mutationFn: () => nodesApi.purgeEdgeCache(node.agent_id, { scope: 'node' }),
    onSuccess: () => push('cache purge queued', 'ok', 'cache://'),
    onError: (e: Error) => push(e.message, 'err', 'cache://'),
  })

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Nginx Proxy Cache</div>
            <div className="scheme">Traefik remains the public edge</div>
          </div>
          {canMutate && (
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <Button size="sm" variant="ghost" leading={<Ic.refresh />} onClick={() => install.mutate()} disabled={install.isPending}>
                reconcile
              </Button>
              <Button size="sm" variant="ghost" onClick={() => test.mutate()} disabled={test.isPending || !cache?.available}>
                test
              </Button>
              <Button size="sm" variant="danger" onClick={() => purge.mutate()} disabled={purge.isPending || !cache?.available}>
                purge
              </Button>
            </div>
          )}
        </div>
        <div className="card-body">
          <div className="gridcols-4">
            <Stat label="mode" value={loading ? 'loading' : mode} />
            <Stat label="available" value={cache?.available ? 'yes' : 'no'} />
            <Stat label="reason" value={cache?.reason || '—'} />
            <Stat label="routes" value={String(routes.length)} />
          </div>
          {canMutate && (
            <div className="row" style={{ gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
              <Button size="sm" variant={mode === 'off' ? 'primary' : 'ghost'} onClick={() => update.mutate('off')} disabled={update.isPending}>
                off
              </Button>
              <Button size="sm" variant={mode === 'headers_only' ? 'primary' : 'ghost'} onClick={() => update.mutate('headers_only')} disabled={update.isPending}>
                headers only
              </Button>
              <Button size="sm" variant={mode === 'proxy_cache' ? 'primary' : 'ghost'} onClick={() => update.mutate('proxy_cache')} disabled={update.isPending}>
                proxy cache
              </Button>
            </div>
          )}
        </div>
      </div>
      <div className="card">
        <div className="card-head"><div className="title">Backend Snapshot</div></div>
        <pre className="code" style={{ margin: 0, maxHeight: 260, overflow: 'auto' }}>{JSON.stringify(cache?.backend ?? {}, null, 2)}</pre>
      </div>
    </div>
  )
}

function EdgeImportDiffPanel({
  node,
  rendered,
  versions,
  loading,
}: {
  node: Node
  rendered?: import('../lib/types').EdgeRenderedConfig
  versions: EdgeConfigVersion[]
  loading: boolean
}) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [showImport, setShowImport] = useState(false)
  const attachmentsQ = useQuery({
    queryKey: ['tunnel-client-attachments', 'server', node.tunnel_server_id],
    queryFn: () => attachApi.list({ tunnel_server_id: node.tunnel_server_id! }),
    enabled: !!node.tunnel_server_id && showImport,
  })
  const rollback = useMutation({
    mutationFn: (version: EdgeConfigVersion) => nodesApi.rollbackEdgeVersion(node.agent_id, version.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['edge-versions', node.agent_id] })
      push('rollback queued', 'ok', 'edge://')
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Rendered Config</div>
            <div className="scheme">{loading ? 'loading' : rendered?.desired_hash || 'not rendered'}</div>
          </div>
          {canMutate && (
            <Button size="sm" variant="ghost" leading={<Ic.download />} onClick={() => setShowImport(true)}>
              import
            </Button>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <KV pairs={[
            ['desired', rendered?.desired_hash || '—', true],
            ['static', rendered?.static_hash || '—', true],
            ['dynamic', rendered?.dynamic_hash || '—', true],
            ['cache', rendered?.cache_hash || '—', true],
          ]} />
        </div>
      </div>
      <div className="card">
        <div className="card-head"><div className="title">Config Versions</div></div>
        <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
          <table className="tbl">
            <thead><tr><th>Created</th><th>Desired</th><th>Applied</th>{canMutate && <th style={{ width: 90 }} />}</tr></thead>
            <tbody>
              {versions.length === 0 && <tr><td colSpan={canMutate ? 4 : 3}><div className="tbl-empty"><h3>No versions</h3></div></td></tr>}
              {versions.map((version) => (
                <tr key={version.id}>
                  <td className="mono">{relTime(version.created_at)}</td>
                  <td className="mono">{version.desired_hash.slice(0, 16)}</td>
                  <td className="mono">{version.applied_at ? relTime(version.applied_at) : '—'}</td>
                  {canMutate && (
                    <td>
                      <Button size="sm" variant="ghost" onClick={() => rollback.mutate(version)} disabled={rollback.isPending}>
                        rollback
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {showImport && node.tunnel_server_id && (
        <TraefikImportDialog
          agentId={node.agent_id}
          serverId={node.tunnel_server_id}
          attachments={attachmentsQ.data ?? []}
          onClose={() => setShowImport(false)}
          onImported={() => {
            qc.invalidateQueries({ queryKey: ['edge-routes', node.agent_id] })
            qc.invalidateQueries({ queryKey: ['node-edge', node.agent_id] })
            setShowImport(false)
          }}
        />
      )}
    </div>
  )
}

function EdgeAdvancedPanel({
  node,
  edge,
  policy,
  rendered,
  versions,
  fragments,
}: {
  node: Node
  edge?: NodeEdge
  policy?: EdgeNodePolicy
  rendered?: import('../lib/types').EdgeRenderedConfig
  versions: EdgeConfigVersion[]
  fragments: EdgeFragment[]
}) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [showFragment, setShowFragment] = useState(false)
  const validate = useMutation({
    mutationFn: () => nodesApi.validateEdge(node.agent_id),
    onSuccess: (result) => push(result.valid ? 'edge config valid' : 'edge config invalid', result.valid ? 'ok' : 'err', 'edge://'),
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Advanced</div>
            <div className="scheme">{versions.length} config versions</div>
          </div>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <EdgeLifecycleActions node={node} edge={edge} />
            {canMutate && (
              <Button size="sm" variant="ghost" onClick={() => validate.mutate()} disabled={validate.isPending}>
                validate
              </Button>
            )}
          </div>
        </div>
        <div className="card-body">
          <div className="gridcols-3">
            <Stat label="mode" value={edge?.mode || '—'} />
            <Stat label="state" value={edge?.state || '—'} />
            <Stat label="desired hash" value={rendered?.desired_hash?.slice(0, 12) || '—'} />
          </div>
        </div>
      </div>
      <div className="gridcols-2">
        <div className="card">
          <div className="card-head"><div className="title">Node Policy JSON</div></div>
          <pre className="code" style={{ margin: 0, maxHeight: 300, overflow: 'auto' }}>{JSON.stringify(policy?.effective ?? {}, null, 2)}</pre>
        </div>
        <div className="card">
          <div className="card-head"><div className="title">Rendered Dynamic JSON</div></div>
          <pre className="code" style={{ margin: 0, maxHeight: 300, overflow: 'auto' }}>{JSON.stringify(rendered?.dynamic ?? {}, null, 2)}</pre>
        </div>
      </div>
      <div className="card">
        <div className="card-head">
          <div className="title">Fragments</div>
          {canMutate && (
            <Button size="sm" variant="ghost" leading={<Ic.plus />} onClick={() => setShowFragment(true)}>
              add fragment
            </Button>
          )}
        </div>
        <div className="tbl-wrap" style={{ border: 0, borderRadius: 0 }}>
          <table className="tbl">
            <thead><tr><th>Name</th><th>Type</th><th>State</th><th>Route</th><th>Error</th></tr></thead>
            <tbody>
              {fragments.length === 0 && <tr><td colSpan={5}><div className="tbl-empty"><h3>No fragments</h3></div></td></tr>}
              {fragments.map((fragment) => (
                <tr key={fragment.id}>
                  <td className="mono">{fragment.name}</td>
                  <td className="mono">{fragment.fragment_type}</td>
                  <td><Badge tone={fragment.validation_state === 'valid' ? 'ok' : 'warn'}>{fragment.validation_state}</Badge></td>
                  <td className="mono">{fragment.route_id?.slice(0, 8) || 'node'}</td>
                  <td className="mono">{fragment.last_error || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {showFragment && (
        <FragmentDialog
          node={node}
          onClose={() => setShowFragment(false)}
          onSaved={() => {
            qc.invalidateQueries({ queryKey: ['edge-fragments', node.agent_id] })
            setShowFragment(false)
          }}
        />
      )}
    </div>
  )
}

function FragmentDialog({ node, onClose, onSaved }: { node: Node; onClose: () => void; onSaved: () => void }) {
  const push = useToast()
  const [name, setName] = useState('')
  const [fragmentType, setFragmentType] = useState('middleware')
  const [content, setContent] = useState('{\n  \n}')
  const save = useMutation({
    mutationFn: () => nodesApi.createEdgeFragment(node.agent_id, {
      name,
      fragment_type: fragmentType,
      content: JSON.parse(content) as Record<string, unknown>,
      enabled: true,
    }),
    onSuccess: () => {
      push('fragment saved', 'ok', 'edge://')
      onSaved()
    },
    onError: (e: Error) => push(e.message, 'err', 'edge://'),
  })

  return (
    <Dialog
      title="Add fragment"
      scheme="advanced config"
      onClose={onClose}
      footer={
        <>
          <span className="left">JSON object content</span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending || !name}>
              {save.isPending ? 'saving...' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <div className="pf-attach-grid">
          <Field label="Name"><Input value={name} onChange={(e) => setName(e.target.value)} mono /></Field>
          <Field label="Type">
            <Select value={fragmentType} onChange={(e) => setFragmentType(e.target.value)}>
              <option value="middleware">middleware</option>
              <option value="service">service</option>
              <option value="router">router</option>
              <option value="tls">tls</option>
              <option value="transport">transport</option>
            </Select>
          </Field>
        </div>
        <Field label="Content">
          <textarea className="textarea input-mono" style={{ minHeight: 220 }} value={content} onChange={(e) => setContent(e.target.value)} />
        </Field>
      </div>
    </Dialog>
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
  agentId,
  serverId,
  attachments,
  onClose,
  onImported,
}: {
  agentId?: string
  serverId: string
  attachments: import('../lib/types').TunnelClientAttachment[]
  onClose: () => void
  onImported: () => void
}) {
  const push = useToast()
  const [attachmentId, setAttachmentId] = useState('')
  const [domainSuffix, setDomainSuffix] = useState('ww.step1.ro')
  const [content, setContent] = useState('')
  const [middlewaresContent, setMiddlewaresContent] = useState('')
  const [activate, setActivate] = useState(false)
  const [overwrite, setOverwrite] = useState(false)
  const [preview, setPreview] = useState<TraefikImportPreview | null>(null)
  const activeAttachment = attachmentId || attachments[0]?.id || ''

  const requestBody = (): TraefikImportRequest => ({
    server_id: serverId,
    attachment_id: activeAttachment,
    content,
    middlewares_content: middlewaresContent || null,
    content_format: 'auto',
    domain_suffix: domainSuffix || null,
    activate,
    overwrite,
  })

  const previewImport = useMutation({
    mutationFn: () => agentId ? nodesApi.previewTraefikImport(agentId, requestBody()) : secApi.previewTraefikImport(requestBody()),
    onSuccess: setPreview,
    onError: (e: Error) => push(e.message, 'err', 'import://'),
  })
  const applyImport = useMutation({
    mutationFn: () => agentId ? nodesApi.applyTraefikImport(agentId, requestBody(), 'apply') : secApi.importTraefik(requestBody()),
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
            {preview ? `${preview.summary.importable}/${preview.summary.routers} importable` : 'paste routes and optional middlewares'}
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
        <Field label="Routes config" hint="Paste external.yml or the dynamic config section that contains routers and services.">
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
        <Field label="Middlewares config" hint="Optional. Paste middlewares.yml so chains like secured and secured-auth can be mapped.">
          <textarea
            className="textarea input-mono"
            style={{ minHeight: 140 }}
            value={middlewaresContent}
            onChange={(e) => {
              setMiddlewaresContent(e.target.value)
              setPreview(null)
            }}
            placeholder={'http:\\n  middlewares:\\n    secured:\\n      chain:\\n        middlewares:\\n          - internal-only@file'}
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
