import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  lanClients as lanApi,
  portForwards as pfApi,
  serviceTemplates as tplApi,
  tunnelClients as tcApi,
  tunnelServerIPs as ipApi,
  tunnelServers as tsApi,
} from '../lib/api'
import {
  Badge,
  Button,
  Dialog,
  Field,
  FilterBar,
  Input,
  K,
  Select,
  StatusDot,
  Toggle,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import type { LanClient, PortForward, ServiceTemplate, TunnelClient, TunnelClientAttachment, TunnelServer, TunnelServerIP } from '../lib/types'

function parsePortRange(s: string): { port: number; portEnd: number | null } {
  const parts = s.trim().split('-')
  if (parts.length === 2) return { port: parseInt(parts[0], 10), portEnd: parseInt(parts[1], 10) }
  return { port: parseInt(parts[0], 10), portEnd: null }
}

type PortToken = { port: number; portEnd: number | null }

function parsePortTokens(s: string): PortToken[] {
  return s
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .map((t) => {
      const parts = t.split('-')
      const port = parseInt(parts[0], 10)
      const portEnd = parts.length === 2 ? parseInt(parts[1], 10) : null
      return { port, portEnd }
    })
}

function isValidPort(p: number): boolean {
  return Number.isFinite(p) && p >= 1 && p <= 65535
}

function tokenLabel(t: PortToken): string {
  return t.portEnd !== null ? `${t.port}-${t.portEnd}` : String(t.port)
}

function portStr(pf: PortForward, field: 'public' | 'dest'): string {
  if (field === 'public') {
    return pf.public_port_end ? `${pf.public_port}-${pf.public_port_end}` : String(pf.public_port)
  }
  return pf.destination_port_end
    ? `${pf.destination_port}-${pf.destination_port_end}`
    : String(pf.destination_port)
}

interface AttachmentLookup {
  attachment: TunnelClientAttachment
  client: TunnelClient | undefined
  server: TunnelServer | undefined
}

function buildAttachmentIndex(
  clients: TunnelClient[],
  servers: TunnelServer[],
): Map<string, AttachmentLookup> {
  const m = new Map<string, AttachmentLookup>()
  for (const c of clients) {
    for (const att of c.attachments) {
      m.set(att.id, {
        attachment: att,
        client: c,
        server: servers.find((s) => s.id === att.tunnel_server_id),
      })
    }
  }
  return m
}

// Pin label resolves the *effective* public IP of the egress pin:
// - If `egress_tunnel_server_ip_id` is set, use that specific IP.
// - Otherwise fall back to the server's primary (MASQUERADE behaviour).
function pinLabelFor(
  lc: LanClient,
  pin: AttachmentLookup | undefined,
  agentName: (id?: string | null) => string,
): string {
  if (!pin) return (lc.egress_attachment_id || '').slice(0, 8)
  const name = agentName(pin.server?.agent_id)
  let pubIP: string | undefined
  if (lc.egress_tunnel_server_ip_id) {
    pubIP = pin.server?.ips.find((i) => i.id === lc.egress_tunnel_server_ip_id)?.address
  }
  pubIP = pubIP || pin.server?.primary_ip || pin.server?.tunnel_network || '?'
  return `${pubIP} (${pin.attachment.wg_interface} · ${name})`
}

function SymmetryHint({
  matched,
  currentAttachmentId,
  attIndex,
  agentName,
}: {
  matched: LanClient | null
  currentAttachmentId: string
  attIndex: Map<string, AttachmentLookup>
  agentName: (id?: string | null) => string
}) {
  if (!matched) return null
  const pinId = matched.egress_attachment_id
  const baseStyle: React.CSSProperties = {
    fontSize: 11,
    fontFamily: 'var(--font-mono)',
    padding: '4px 8px',
    borderRadius: 4,
    display: 'inline-block',
  }
  if (!pinId) {
    return (
      <span style={{ ...baseStyle, color: 'var(--fg-3)' }}>
        host {matched.lan_ip} not pinned · this forward sets inbound only
      </span>
    )
  }
  const pin = attIndex.get(pinId)
  const pinLabel = pinLabelFor(matched, pin, agentName)
  if (currentAttachmentId === pinId) {
    return (
      <span style={{ ...baseStyle, color: 'var(--ok)', background: 'var(--ok-bg)' }}>
        ↔ symmetric · inbound + outbound both via {pinLabel}
      </span>
    )
  }
  const cur = attIndex.get(currentAttachmentId)
  const curLabel = cur
    ? `${cur.server?.primary_ip || agentName(cur.server?.agent_id)} (${cur.attachment.wg_interface} · ${agentName(cur.server?.agent_id)})`
    : '—'
  return (
    <span style={{ ...baseStyle, color: 'var(--warn)', background: 'var(--warn-bg)' }}>
      ⚠ asymmetric · inbound via {curLabel}, host's egress pinned to {pinLabel}
    </span>
  )
}

// useLanClientsByIp aggregates discovered LAN clients across all gateway
// clients into a single Map<lan_ip, LanClient>. Used by the port-forward
// dialogs to detect when a destination_ip belongs to a pinned host so the
// dialog can default attachment + ip to match the host's egress pin.
function useLanClientsByIp(clients: TunnelClient[]): Map<string, LanClient> {
  const gatewayClients = useMemo(() => clients.filter((c) => c.is_gateway), [clients])
  const queries = useQueries({
    queries: gatewayClients.map((c) => ({
      queryKey: ['lan-clients', c.id],
      queryFn: () => lanApi.list(c.id),
      
    })),
  })
  return useMemo(() => {
    const m = new Map<string, LanClient>()
    for (const q of queries) {
      for (const lc of q.data ?? []) m.set(lc.lan_ip, lc)
    }
    return m
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queries.map((q) => q.dataUpdatedAt).join(',')])
}

export default function PortForwards() {
  const qc = useQueryClient()
  const push = useToast()
  const [params, setParams] = useSearchParams()
  const [filter, setFilter] = useState('')
  const [serverF, setServerF] = useState('all')
  const [protoF, setProtoF] = useState('all')
  const [activeF, setActiveF] = useState('all')
  const [groupBy, setGroupBy] = useState<'server' | 'client' | 'none'>('server')
  const [showNew, setShowNew] = useState(params.get('new') === '1')
  const [editing, setEditing] = useState<PortForward | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (showNew && params.get('new') !== '1') {
      const next = new URLSearchParams(params)
      next.set('new', '1')
      setParams(next, { replace: true })
    } else if (!showNew && params.get('new') === '1') {
      const next = new URLSearchParams(params)
      next.delete('new')
      setParams(next, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showNew])

  const pfs = useQuery({ queryKey: ['port-forwards'], queryFn: () => pfApi.list() }).data ?? []
  const servers = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const clients = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []

  const attIndex = useMemo(() => buildAttachmentIndex(clients, servers), [clients, servers])

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (e.key === '/') {
        e.preventDefault()
        filterRef.current?.focus()
      }
      if (e.key === 'n' || e.key === 'N') {
        e.preventDefault()
        setShowNew(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const filtered = useMemo(
    () =>
      pfs.filter((p) => {
        const lookup = attIndex.get(p.attachment_id)
        if (serverF !== 'all' && lookup?.server?.id !== serverF) return false
        if (protoF !== 'all' && p.protocol !== protoF) return false
        if (activeF === 'active' && !p.active) return false
        if (activeF === 'disabled' && p.active) return false
        if (filter) {
          const f = filter.toLowerCase()
          const ca = agents.find((x) => x.id === lookup?.client?.agent_id)
          return [String(p.public_port), p.destination_ip, String(p.destination_port), p.description, ca?.name]
            .filter(Boolean)
            .some((x) => String(x).toLowerCase().includes(f))
        }
        return true
      }),
    [pfs, serverF, protoF, activeF, filter, agents, attIndex],
  )

  const groups = useMemo(() => {
    if (groupBy === 'none') return [{ key: 'all', label: null as React.ReactNode, rows: filtered }]
    if (groupBy === 'server') {
      return servers
        .map((s) => ({
          key: s.id,
          label: <ServerLabel server={s} agentName={agentName(s.agent_id)} agentStatus={agents.find((x) => x.id === s.agent_id)?.status} />,
          rows: filtered.filter((p) => attIndex.get(p.attachment_id)?.server?.id === s.id),
        }))
        .filter((g) => g.rows.length > 0)
    }
    const ids = [...new Set(filtered.map((p) => attIndex.get(p.attachment_id)?.client?.id).filter(Boolean) as string[])]
    return ids.map((cid) => {
      const c = clients.find((x) => x.id === cid)
      return {
        key: cid,
        label: (
          <span>
            <span className="dot ok"></span> <span className="mono">{agentName(c?.agent_id)}</span>
          </span>
        ),
        rows: filtered.filter((p) => attIndex.get(p.attachment_id)?.client?.id === cid),
      }
    })
  }, [groupBy, filtered, servers, clients, agents, attIndex])

  const toggle = useMutation({
    mutationFn: (pf: PortForward) => pfApi.update(pf.id, { active: !pf.active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['port-forwards'] }),
    onError: (e: Error) => push(e.message, 'err', 'pf://'),
  })
  const del = useMutation({
    mutationFn: pfApi.del,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['port-forwards'] })
      qc.invalidateQueries({ queryKey: ['tunnel-server-ips'] })
      push('forward deleted', 'err', 'pf://')
    },
    onError: (e: Error) => push(e.message, 'err', 'pf://'),
  })

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>port-forwards</span>
          </div>
          <h1 className="page-title">Port forwards</h1>
          <p className="page-sub">
            Map <span className="mono" style={{ color: 'var(--fg-1)' }}>server_public_ip:port</span> →{' '}
            <span className="mono" style={{ color: 'var(--fg-1)' }}>client_internal_ip:port</span>.
          </p>
        </div>
        <div className="page-actions">
          <span className="filter-chip">
            <span className="label">group</span>
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as typeof groupBy)}>
              <option value="server">by server</option>
              <option value="client">by client</option>
              <option value="none">flat</option>
            </select>
          </span>
          <Button variant="primary" leading={<Ic.plus />} onClick={() => setShowNew(true)}>
            New forward<span className="kbd-inline">N</span>
          </Button>
        </div>
      </div>

      <FilterBar
        filterRef={filterRef}
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'server',
            value: serverF,
            onChange: setServerF,
            options: [['all', 'all'], ...servers.map((s) => [s.id, agentName(s.agent_id)] as [string, string])],
          },
          {
            label: 'protocol',
            value: protoF,
            onChange: setProtoF,
            options: [
              ['all', 'all'],
              ['tcp', 'tcp'],
              ['udp', 'udp'],
            ],
          },
          {
            label: 'state',
            value: activeF,
            onChange: setActiveF,
            options: [
              ['all', 'all'],
              ['active', 'active'],
              ['disabled', 'disabled'],
            ],
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{pfs.length}
          </span>
        }
      />

      {groups.map((g) => (
        <div key={g.key} className="tbl-wrap" style={{ marginBottom: 16 }}>
          {g.label && (
            <div
              style={{
                padding: '10px 14px',
                borderBottom: '1px solid var(--border-soft)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'var(--bg-1)',
              }}
            >
              <div className="row" style={{ gap: 8 }}>
                {g.label}
              </div>
              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
                {g.rows.length} rules
              </span>
            </div>
          )}
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 26 }}></th>
                <th style={{ width: 70 }}>Proto</th>
                <th>Public</th>
                <th style={{ width: 28, textAlign: 'center' }}></th>
                <th>Destination</th>
                <th>Client</th>
                <th>Description</th>
                <th style={{ width: 70 }}>State</th>
                <th style={{ width: 110, textAlign: 'right' }}></th>
              </tr>
            </thead>
            <tbody>
              {g.rows.map((p) => {
                const lookup = attIndex.get(p.attachment_id)
                const c = lookup?.client
                const ca = agents.find((x) => x.id === c?.agent_id)
                const s = lookup?.server
                const ip = s?.ips.find((i) => i.id === p.tunnel_server_ip_id)
                return (
                  <tr key={p.id} style={{ opacity: p.active ? 1 : 0.55 }}>
                    <td data-label="">
                      <span className={`dot ${p.active ? 'ok' : ''}`}></span>
                    </td>
                    <td data-label="proto">
                      <Badge tone={p.protocol === 'tcp' ? 'info' : 'peer'}>{p.protocol}</Badge>
                    </td>
                    <td data-label="public" className="mono">
                      <span style={{ color: 'var(--fg-3)' }}>{ip?.address || s?.primary_ip || '*'}</span>
                      <span style={{ color: 'var(--fg-3)' }}>:</span>
                      <span style={{ color: 'var(--fg-0)', fontWeight: 500 }}>{portStr(p, 'public')}</span>
                    </td>
                    <td data-label="" style={{ textAlign: 'center', color: 'var(--fg-3)' }}>
                      <Ic.arrow s={10} />
                    </td>
                    <td data-label="dest" className="mono">
                      <span style={{ color: 'var(--fg-1)' }}>{p.destination_ip}</span>
                      <span style={{ color: 'var(--fg-3)' }}>:</span>
                      <span style={{ color: 'var(--fg-0)', fontWeight: 500 }}>{portStr(p, 'dest')}</span>
                    </td>
                    <td data-label="client">
                      <span className="mono" style={{ color: 'var(--fg-1)' }}>
                        {ca?.name || '—'}
                      </span>
                      {lookup?.attachment && (
                        <span className="scheme" style={{ marginLeft: 6, fontSize: 11 }}>
                          {lookup.attachment.wg_interface}
                        </span>
                      )}
                    </td>
                    <td data-label="desc" style={{ color: 'var(--fg-2)' }}>
                      {p.description || <span style={{ color: 'var(--fg-3)' }}>—</span>}
                    </td>
                    <td data-label="active">
                      <Toggle on={p.active} onChange={() => toggle.mutate(p)} />
                    </td>
                    <td data-label="">
                      <div className="row-actions">
                        <Button size="sm" variant="ghost" leading={<Ic.edit />} onClick={() => setEditing(p)}>
                          edit
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          leading={<Ic.trash />}
                          style={{ color: 'var(--err)' }}
                          onClick={() => {
                            if (confirm(`Delete forward :${p.public_port}?`)) del.mutate(p.id)
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ))}

      {filtered.length === 0 && (
        <div className="empty">
          <div className="glyph">
            <Ic.forward s={16} />
          </div>
          <h3>No port forwards yet</h3>
          <p>
            A port forward maps a public address on a tunnel server to an internal address on a client. The bread and
            butter of WireWarp.
          </p>
          <Button variant="primary" leading={<Ic.plus />} onClick={() => setShowNew(true)}>
            Create first forward
          </Button>
        </div>
      )}

      <div style={{ marginTop: 4, fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
        <K>/</K> filter · <K>N</K> new · click edit on a row to modify
      </div>

      {showNew && <NewForwardDialog onClose={() => setShowNew(false)} />}
      {editing && <EditForwardDialog pf={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function ServerLabel({
  server,
  agentName,
  agentStatus,
}: {
  server: TunnelServer
  agentName: string
  agentStatus?: string
}) {
  return (
    <span className="row" style={{ gap: 8 }}>
      <StatusDot status={agentStatus || 'disconnected'} label={false} />
      <span className="mono" style={{ fontSize: 13 }}>
        {agentName}
      </span>
      <span className="scheme" style={{ fontSize: 12 }}>
        {server.primary_ip || server.tunnel_network}
      </span>
      <span style={{ color: 'var(--fg-3)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
        · {server.tunnel_network}
      </span>
    </span>
  )
}

function NewForwardDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const servers = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const clients = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []
  const templates = useQuery({ queryKey: ['service-templates'], queryFn: tplApi.list }).data ?? []
  const allPf = useQuery({ queryKey: ['port-forwards'], queryFn: () => pfApi.list() }).data ?? []

  const attIndex = useMemo(() => buildAttachmentIndex(clients, servers), [clients, servers])
  const allAttachments = useMemo<AttachmentLookup[]>(
    () => Array.from(attIndex.values()),
    [attIndex],
  )
  const lanByIp = useLanClientsByIp(clients)

  const [form, setForm] = useState({
    attachment_id: allAttachments[0]?.attachment.id || '',
    tunnel_server_ip_id: '',
    protocol: 'tcp' as 'tcp' | 'udp',
    public_port: '',
    destination_ip: '',
    destination_port: '',
    description: '',
  })
  // Track whether the operator has manually overridden the attachment
  // selection so we don't keep auto-syncing it as they edit.
  const userTouchedAttachment = useRef(false)
  const set = (k: keyof typeof form, v: string) => setForm((f) => ({ ...f, [k]: v }))

  // Default attachment when data loads
  useEffect(() => {
    if (!form.attachment_id && allAttachments[0]) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      set('attachment_id', allAttachments[0].attachment.id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allAttachments, form.attachment_id])

  const lookup = attIndex.get(form.attachment_id)
  const server = lookup?.server
  const client = lookup?.client
  const attachment = lookup?.attachment

  // Destination-IP suggestions: LAN clients discovered behind the selected
  // attachment's tunnel client, plus the attachment's own tunnel IP (a
  // service running on the client agent itself is also a valid target).
  const destSuggestions = useMemo(() => {
    type Sug = { ip: string; label: string }
    const out: Sug[] = []
    if (attachment) {
      out.push({ ip: attachment.tunnel_ip, label: `${agentName(client?.agent_id)} (tunnel)` })
    }
    if (client) {
      const lans = Array.from(lanByIp.values()).filter((lc) => lc.tunnel_client_id === client.id)
      lans.sort((a, b) => (a.hostname || a.lan_ip).localeCompare(b.hostname || b.lan_ip))
      for (const lc of lans) {
        out.push({
          ip: lc.lan_ip,
          label: lc.hostname ? `${lc.hostname} · LAN` : `LAN (${lc.mac || '?'})`,
        })
      }
    }
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attachment?.id, client?.id, lanByIp])

  const ipsQ = useQuery({
    queryKey: ['tunnel-server-ips', server?.id],
    queryFn: () => ipApi.list(server?.id),
    enabled: !!server?.id,
  })
  const ips = ipsQ.data ?? []
  const ip = ips.find((i) => i.id === form.tunnel_server_ip_id) || ips.find((i) => i.is_primary)

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  // Default destination_ip from the attachment's tunnel_ip — only when the
  // attachment changes. Don't refire when the operator clears the field
  // themselves, or the input would snap back to the tunnel IP on every delete.
  useEffect(() => {
    if (attachment && !form.destination_ip) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      set('destination_ip', attachment.tunnel_ip)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attachment?.id])

  // When destination_ip resolves to a pinned LAN client, mirror both its
  // egress attachment AND its IP pin into the form so inbound + outbound
  // use the same VPS *and* the same public IP by default. Operator can
  // still override — once they do, we stop auto-syncing for this dialog.
  const matchedLanClient = lanByIp.get(form.destination_ip) ?? null
  useEffect(() => {
    if (userTouchedAttachment.current) return
    if (!matchedLanClient?.egress_attachment_id) return
    const targetIp = matchedLanClient.egress_tunnel_server_ip_id || ''
    if (
      form.attachment_id === matchedLanClient.egress_attachment_id &&
      form.tunnel_server_ip_id === targetIp
    ) {
      return
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setForm((f) => ({
      ...f,
      attachment_id: matchedLanClient.egress_attachment_id!,
      tunnel_server_ip_id: targetIp,
    }))
  }, [matchedLanClient, form.attachment_id, form.tunnel_server_ip_id])

  function applyTemplate(t: ServiceTemplate) {
    const ports = t.ports
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .join(',')
    const firstPort = ports.split(',')[0] || ''
    setForm((f) => ({
      ...f,
      protocol: t.protocol === 'both' ? 'tcp' : (t.protocol as 'tcp' | 'udp'),
      public_port: ports,
      destination_port: firstPort,
      description: t.name,
    }))
  }

  function nextFreePort() {
    const used = new Set(allPf.map((p) => p.public_port))
    let p = 10000
    while (used.has(p)) p++
    set('public_port', String(p))
    if (!form.destination_port) set('destination_port', String(p))
  }

  const create = useMutation({
    mutationFn: async () => {
      const tokens = parsePortTokens(form.public_port)
      if (tokens.length === 0) throw new Error('no ports specified')
      for (const t of tokens) {
        if (!isValidPort(t.port)) throw new Error(`invalid port: ${form.public_port}`)
        if (t.portEnd !== null && (!isValidPort(t.portEnd) || t.portEnd < t.port))
          throw new Error(`invalid range: ${tokenLabel(t)}`)
      }
      const multi = tokens.length > 1
      const dstSingle = multi ? null : parsePortRange(form.destination_port)

      const created: PortForward[] = []
      const failed: { token: PortToken; err: string }[] = []
      for (const t of tokens) {
        try {
          const pf = await pfApi.create({
            attachment_id: form.attachment_id,
            tunnel_server_ip_id: form.tunnel_server_ip_id || null,
            protocol: form.protocol,
            public_port: t.port,
            public_port_end: t.portEnd,
            destination_ip: form.destination_ip,
            destination_port: multi ? t.port : dstSingle!.port,
            destination_port_end: multi ? t.portEnd : dstSingle!.portEnd,
            description: form.description || null,
          })
          created.push(pf)
        } catch (e) {
          failed.push({ token: t, err: (e as Error).message })
        }
      }
      return { created, failed }
    },
    onSuccess: ({ created, failed }) => {
      qc.invalidateQueries({ queryKey: ['port-forwards'] })
      qc.invalidateQueries({ queryKey: ['tunnel-server-ips'] })
      if (created.length > 0) {
        const summary = created
          .map((p) => (p.public_port_end ? `:${p.public_port}-${p.public_port_end}` : `:${p.public_port}`))
          .join(' ')
        push(`forward created · ${summary}`, 'ok', 'pf://')
      }
      for (const f of failed) {
        const tag = `:${tokenLabel(f.token)}`
        const msg = f.err.includes('409') ? 'duplicate' : f.err
        push(`failed ${tag} · ${msg}`, 'err', 'pf://')
      }
      if (failed.length === 0) onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'pf://'),
  })

  const pubTokens = parsePortTokens(form.public_port)
  const isMultiPort = pubTokens.length > 1
  const ok = !!(
    form.attachment_id &&
    form.public_port &&
    form.destination_ip &&
    (isMultiPort || form.destination_port)
  )

  return (
    <Dialog
      title="New port forward"
      scheme="POST /port-forwards"
      onClose={onClose}
      width={780}
      footer={
        <>
          <span className="left">
            <K>↵</K> to save · <K>Esc</K> to cancel
          </span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!ok || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? 'creating…' : 'Create forward'} <Ic.enter />
            </Button>
          </div>
        </>
      }
    >
      {templates.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div className="field-label" style={{ marginBottom: 6 }}>Quick templates</div>
          <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {templates.map((t) => (
              <button
                key={t.id}
                className="filter-chip"
                onClick={() => applyTemplate(t)}
                style={{ cursor: 'pointer' }}
              >
                <span className="mono" style={{ color: 'var(--fg-0)' }}>{t.name}</span>
                <span className="scheme">{t.protocol}/{t.ports}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="pf-attach-grid">
        <Field label="Attachment" hint="One client peering with one server. Manage attachments on Tunnel clients.">
          <Select
            value={form.attachment_id}
            onChange={(e) => {
              userTouchedAttachment.current = true
              set('attachment_id', e.target.value)
            }}
          >
            <option value="">— select —</option>
            {allAttachments.map((l) => (
              <option key={l.attachment.id} value={l.attachment.id}>
                {agentName(l.server?.agent_id)} → {agentName(l.client?.agent_id)} ({l.attachment.tunnel_ip} · {l.attachment.wg_interface})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="On public IP">
          <Select
            value={form.tunnel_server_ip_id}
            onChange={(e) => set('tunnel_server_ip_id', e.target.value)}
          >
            <option value="">primary (default)</option>
            {ips.map((i: TunnelServerIP) => (
              <option key={i.id} value={i.id}>
                {i.address}
                {i.is_primary ? ' · primary' : ''}
                {i.label ? ` (${i.label})` : ''}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <SymmetryHint
        matched={matchedLanClient}
        currentAttachmentId={form.attachment_id}
        attIndex={attIndex}
        agentName={agentName}
      />
      <div style={{ height: 6 }}></div>

      <div className="pf-form-grid">
        <Field label="Protocol">
          <Select value={form.protocol} onChange={(e) => set('protocol', e.target.value)}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </Select>
        </Field>
        <Field
          label="Public port"
          hint="single (25565), range (50000-50100), or list (80,443,8080) — one rule per entry"
        >
          <div className="row" style={{ gap: 6 }}>
            <Input
              mono
              placeholder="e.g. 25565"
              value={form.public_port}
              onChange={(e) => set('public_port', e.target.value)}
              style={{ flex: 1 }}
            />
            <Button size="sm" variant="ghost" onClick={nextFreePort} title="next free port" type="button">
              free
            </Button>
          </div>
        </Field>
        <div style={{ paddingBottom: 7, color: 'var(--fg-3)', textAlign: 'center' }}>
          <Ic.arrow />
        </div>
        <Field
          label="Destination IP"
          hint={
            destSuggestions.length > 1
              ? `${destSuggestions.length - 1} LAN client${destSuggestions.length === 2 ? '' : 's'} behind this attachment`
              : undefined
          }
        >
          {(() => {
            const isCustom =
              destSuggestions.length === 0 ||
              !destSuggestions.some((s) => s.ip === form.destination_ip)
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <Select
                  value={isCustom ? '__custom__' : form.destination_ip}
                  onChange={(e) => {
                    const v = e.target.value
                    set('destination_ip', v === '__custom__' ? '' : v)
                  }}
                >
                  {destSuggestions.map((s) => (
                    <option key={s.ip} value={s.ip}>
                      {s.label} — {s.ip}
                    </option>
                  ))}
                  <option value="__custom__">— custom IP —</option>
                </Select>
                {isCustom && (
                  <Input
                    mono
                    placeholder="10.21.0.x"
                    value={form.destination_ip}
                    onChange={(e) => set('destination_ip', e.target.value)}
                  />
                )}
              </div>
            )
          })()}
        </Field>
        <Field
          label="Destination port"
          hint={isMultiPort ? 'auto: each public port maps to itself (port-preserve)' : undefined}
        >
          <Input
            mono
            placeholder={isMultiPort ? '— port-preserve —' : 'e.g. 25565'}
            value={isMultiPort ? '' : form.destination_port}
            onChange={(e) => set('destination_port', e.target.value)}
            disabled={isMultiPort}
          />
        </Field>
      </div>

      <Field label="Description (optional)">
        <Input
          placeholder="What is this forward for?"
          value={form.description}
          onChange={(e) => set('description', e.target.value)}
        />
      </Field>

      {ok && (
        <div className="outcome" style={{ marginTop: 14 }}>
          {isMultiPort ? (
            <>
              {pubTokens.map((t) => (
                <div className="ln" key={tokenLabel(t)}>
                  <span className="k">iptables</span>
                  <span className="v">
                    -t nat -A WIREWARP-PRE -d {ip?.address || server?.primary_ip || '*'} -p {form.protocol} --dport{' '}
                    {tokenLabel(t).replace('-', ':')} -j DNAT --to-destination {form.destination_ip}:{tokenLabel(t)}
                  </span>
                </div>
              ))}
              <div className="english">
                Creates <span className="accent">{pubTokens.length} rules</span>. Inbound{' '}
                <span className="accent">{form.protocol.toUpperCase()}</span> traffic to{' '}
                <span className="accent">
                  {ip?.address || server?.primary_ip || '*'}:{pubTokens.map(tokenLabel).join(',')}
                </span>{' '}
                forwards through <span className="accent">{agentName(server?.agent_id)}</span> to{' '}
                <span className="accent">{form.destination_ip}</span> on the same ports (port-preserve).
              </div>
            </>
          ) : (
            <>
              <div className="ln">
                <span className="k">iptables</span>
                <span className="v">
                  -t nat -A WIREWARP-PRE -d {ip?.address || server?.primary_ip || '*'} -p {form.protocol} --dport{' '}
                  {form.public_port} -j DNAT --to-destination {form.destination_ip}:{form.destination_port}
                </span>
              </div>
              <div className="english">
                Inbound <span className="accent">{form.protocol.toUpperCase()}</span> traffic to{' '}
                <span className="accent">
                  {ip?.address || server?.primary_ip || '*'}:{form.public_port}
                </span>{' '}
                forwards through <span className="accent">{agentName(server?.agent_id)}</span> to{' '}
                <span className="accent">
                  {form.destination_ip}:{form.destination_port}
                </span>{' '}
                on {agentName(client?.agent_id)}.
              </div>
            </>
          )}
        </div>
      )}
    </Dialog>
  )
}

function EditForwardDialog({ pf, onClose }: { pf: PortForward; onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const servers = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const clients = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []
  const attIndex = useMemo(() => buildAttachmentIndex(clients, servers), [clients, servers])
  const lookup = attIndex.get(pf.attachment_id)
  const lanByIp = useLanClientsByIp(clients)
  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }
  const ipsQ = useQuery({
    queryKey: ['tunnel-server-ips', lookup?.server?.id],
    queryFn: () => ipApi.list(lookup?.server?.id),
    enabled: !!lookup?.server?.id,
  })
  const ips = ipsQ.data ?? []
  const [form, setForm] = useState({
    tunnel_server_ip_id: pf.tunnel_server_ip_id || '',
    protocol: pf.protocol,
    public_port: pf.public_port_end ? `${pf.public_port}-${pf.public_port_end}` : String(pf.public_port),
    destination_ip: pf.destination_ip,
    destination_port: pf.destination_port_end
      ? `${pf.destination_port}-${pf.destination_port_end}`
      : String(pf.destination_port),
    description: pf.description || '',
  })

  const destSuggestions = useMemo(() => {
    type Sug = { ip: string; label: string }
    const out: Sug[] = []
    if (lookup?.attachment) {
      out.push({
        ip: lookup.attachment.tunnel_ip,
        label: `${agentName(lookup.client?.agent_id)} (tunnel)`,
      })
    }
    if (lookup?.client) {
      const clientId = lookup.client.id
      const lans = Array.from(lanByIp.values()).filter((lc) => lc.tunnel_client_id === clientId)
      lans.sort((a, b) => (a.hostname || a.lan_ip).localeCompare(b.hostname || b.lan_ip))
      for (const lc of lans) {
        out.push({
          ip: lc.lan_ip,
          label: lc.hostname ? `${lc.hostname} · LAN` : `LAN (${lc.mac || '?'})`,
        })
      }
    }
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lookup?.attachment?.id, lookup?.client?.id, lanByIp])

  const save = useMutation({
    mutationFn: () => {
      const pub = parsePortRange(form.public_port)
      const dst = parsePortRange(form.destination_port)
      return pfApi.update(pf.id, {
        tunnel_server_ip_id: form.tunnel_server_ip_id || null,
        protocol: form.protocol,
        public_port: pub.port,
        public_port_end: pub.portEnd,
        destination_ip: form.destination_ip,
        destination_port: dst.port,
        destination_port_end: dst.portEnd,
        description: form.description || null,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['port-forwards'] })
      qc.invalidateQueries({ queryKey: ['tunnel-server-ips'] })
      push('forward updated', 'ok', 'pf://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'pf://'),
  })

  return (
    <Dialog
      title="Edit port forward"
      scheme={`PATCH /port-forwards/${pf.id.slice(0, 8)}`}
      onClose={onClose}
      width={620}
      footer={
        <>
          <span className="left">id: <span className="mono">{pf.id}</span></span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending}>
              {save.isPending ? 'saving…' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="gridcols-2">
        <Field label="Attachment">
          <Input
            mono
            disabled
            value={
              lookup
                ? `${lookup.server?.tunnel_network || '?'} → ${lookup.attachment.tunnel_ip} (${lookup.attachment.wg_interface})`
                : pf.attachment_id
            }
          />
        </Field>
        <Field label="On public IP">
          <Select
            value={form.tunnel_server_ip_id}
            onChange={(e) => setForm({ ...form, tunnel_server_ip_id: e.target.value })}
          >
            <option value="">primary (default)</option>
            {ips.map((i) => (
              <option key={i.id} value={i.id}>
                {i.address}
                {i.is_primary ? ' · primary' : ''}
              </option>
            ))}
          </Select>
        </Field>
        <div style={{ gridColumn: '1 / -1' }}>
          <SymmetryHint
            matched={lanByIp.get(form.destination_ip) ?? null}
            currentAttachmentId={pf.attachment_id}
            attIndex={attIndex}
            agentName={agentName}
          />
        </div>
        <Field label="Protocol">
          <Select
            value={form.protocol}
            onChange={(e) => setForm({ ...form, protocol: e.target.value as 'tcp' | 'udp' })}
          >
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </Select>
        </Field>
        <Field label="Public port">
          <Input
            mono
            value={form.public_port}
            onChange={(e) => setForm({ ...form, public_port: e.target.value })}
          />
        </Field>
        <Field
          label="Destination IP"
          hint={
            destSuggestions.length > 1
              ? `${destSuggestions.length - 1} LAN client${destSuggestions.length === 2 ? '' : 's'} behind this attachment`
              : undefined
          }
        >
          {(() => {
            const isCustom =
              destSuggestions.length === 0 ||
              !destSuggestions.some((s) => s.ip === form.destination_ip)
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <Select
                  value={isCustom ? '__custom__' : form.destination_ip}
                  onChange={(e) => {
                    const v = e.target.value
                    setForm({ ...form, destination_ip: v === '__custom__' ? '' : v })
                  }}
                >
                  {destSuggestions.map((s) => (
                    <option key={s.ip} value={s.ip}>
                      {s.label} — {s.ip}
                    </option>
                  ))}
                  <option value="__custom__">— custom IP —</option>
                </Select>
                {isCustom && (
                  <Input
                    mono
                    placeholder="10.21.0.x"
                    value={form.destination_ip}
                    onChange={(e) => setForm({ ...form, destination_ip: e.target.value })}
                  />
                )}
              </div>
            )
          })()}
        </Field>
        <Field label="Destination port">
          <Input
            mono
            value={form.destination_port}
            onChange={(e) => setForm({ ...form, destination_port: e.target.value })}
          />
        </Field>
        <Field label="Description">
          <Input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
        </Field>
      </div>
    </Dialog>
  )
}
