import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  dns as dnsApi,
  lanClients as lanApi,
  portForwards as pfApi,
  settings as settingsApi,
  tunnelClients as tcApi,
  tunnelServers as tsApi,
} from '../lib/api'
import {
  Badge,
  Button,
  Dialog,
  Field,
  FilterBar,
  Input,
  IpChip,
  Select,
  relTime,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import type { DnsRecordRef, LanClient, PortForward, TunnelClient, TunnelClientAttachment, TunnelServer } from '../lib/types'

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

// Encode an egress pin as a single Select value: `attId|ipId`. Empty
// means "no pin" (home ISP). Empty ipId means "attachment routing only,
// VPS picks source via MASQUERADE" — kept for back-compat with the
// pre-multi-IP-pin UI; new dropdowns always emit a specific ipId.
function makeEgressValue(lc: LanClient): string {
  if (!lc.egress_attachment_id) return ''
  return `${lc.egress_attachment_id}|${lc.egress_tunnel_server_ip_id || ''}`
}

function parseEgressValue(v: string): { att: string | null; ip: string | null } {
  if (!v) return { att: null, ip: null }
  const [att, ip] = v.split('|')
  return { att: att || null, ip: ip || null }
}

type SymmetryStatus = 'none' | 'symmetric' | 'asymmetric'

function symmetryFor(
  pf: PortForward,
  lc: LanClient,
): SymmetryStatus {
  if (!lc.egress_attachment_id) return 'none'
  return pf.attachment_id === lc.egress_attachment_id ? 'symmetric' : 'asymmetric'
}

export default function LanClients() {
  const qc = useQueryClient()
  const push = useToast()
  const [filter, setFilter] = useState('')
  const [pinFilter, setPinFilter] = useState('all')
  const [activityFilter, setActivityFilter] = useState('all')
  const [gatewayFilter, setGatewayFilter] = useState('all')
  const [showAdd, setShowAdd] = useState(false)
  const [dnsEditing, setDnsEditing] = useState<LanClient | null>(null)
  const [metaEditing, setMetaEditing] = useState<LanClient | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)

  const settingsQ = useQuery({ queryKey: ['settings'], queryFn: settingsApi.get })
  const dnsConfigured = !!(settingsQ.data && settingsQ.data.dns_provider && settingsQ.data.cloudflare_token_set)

  const lanQ = useQuery({
    queryKey: ['lan-clients', 'all'],
    queryFn: lanApi.listAll,
    
  })
  const clientsQ = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list })
  const serversQ = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list })
  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list })
  const pfQ = useQuery({ queryKey: ['port-forwards'], queryFn: () => pfApi.list() })

  const lan = lanQ.data ?? []
  const clients = clientsQ.data ?? []
  const servers = serversQ.data ?? []
  const agents = agentsQ.data ?? []
  const pfs = pfQ.data ?? []

  const attIndex = useMemo(() => buildAttachmentIndex(clients, servers), [clients, servers])
  const gatewayClients = useMemo(() => clients.filter((c) => c.is_gateway), [clients])

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  // One <option> per (attachment, public IP). Setting an ipId installs a
  // per-host SNAT rule on the VPS so outbound appears as that specific
  // IP. ipId='' means attachment routing pin only (MASQUERADE → primary).
  function attachmentOptions(att: TunnelClientAttachment): { value: string; label: string }[] {
    const s = servers.find((x) => x.id === att.tunnel_server_id)
    const name = s ? agentName(s.agent_id) : 'server'
    const ips = s?.ips ?? []
    if (ips.length === 0) {
      const pub = s?.primary_ip || s?.tunnel_network || '—'
      return [{ value: `${att.id}|`, label: `${pub} (${att.wg_interface} · ${name})` }]
    }
    return ips.map((ip) => ({
      value: `${att.id}|${ip.id}`,
      label: `${ip.address}${ip.is_primary ? ' · primary' : ''} (${att.wg_interface} · ${name})`,
    }))
  }

  // Forwards keyed by destination_ip for quick lookup per LAN host.
  const forwardsByIp = useMemo(() => {
    const m = new Map<string, PortForward[]>()
    for (const pf of pfs) {
      const arr = m.get(pf.destination_ip) ?? []
      arr.push(pf)
      m.set(pf.destination_ip, arr)
    }
    return m
  }, [pfs])

  const filtered = useMemo(() => {
    return lan.filter((c) => {
      if (gatewayFilter !== 'all' && c.tunnel_client_id !== gatewayFilter) return false
      if (pinFilter === 'pinned' && !c.egress_attachment_id) return false
      if (pinFilter === 'unpinned' && c.egress_attachment_id) return false
      if (activityFilter !== 'all') {
        const ageMs = Date.now() - new Date(c.last_seen).getTime()
        const isFresh = ageMs < 60_000
        if (activityFilter === 'active' && !isFresh) return false
        if (activityFilter === 'idle' && isFresh) return false
      }
      if (filter) {
        const f = filter.toLowerCase()
        const hay = [c.lan_ip, c.mac, c.hostname].filter(Boolean).join(' ').toLowerCase()
        return hay.includes(f)
      }
      return true
    })
  }, [lan, gatewayFilter, pinFilter, activityFilter, filter])

  const pinnedCount = lan.filter((c) => c.egress_attachment_id).length

  const setEgress = useMutation({
    mutationFn: (vars: { lc: LanClient; value: string }) => {
      const { att, ip } = parseEgressValue(vars.value)
      return lanApi.setEgress(vars.lc.tunnel_client_id, vars.lc.id, att, ip)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients'] })
      push('egress updated', 'ok', 'lan://')
    },
    onError: (e: Error) => push(e.message, 'err', 'lan://'),
  })

  const del = useMutation({
    mutationFn: (lc: LanClient) => lanApi.del(lc.tunnel_client_id, lc.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['lan-clients'] }),
    onError: (e: Error) => push(e.message, 'err', 'lan://'),
  })

  // "Fix" a single asymmetric forward by aligning its (attachment_id,
  // tunnel_server_ip_id) with the host's egress pin. Auto-migration on
  // egress change should normally already cover this — the button is a
  // recovery path for forwards left behind (e.g. agent was offline when
  // egress changed, or a unique-constraint conflict prevented bulk move).
  const fixSym = useMutation({
    mutationFn: ({ pf, lc }: { pf: PortForward; lc: LanClient }) =>
      pfApi.update(pf.id, {
        attachment_id: lc.egress_attachment_id,
        tunnel_server_ip_id: lc.egress_tunnel_server_ip_id,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['port-forwards'] })
      push('forward migrated', 'ok', 'pf://')
    },
    onError: (e: Error) => push(e.message, 'err', 'pf://'),
  })

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
        setShowAdd(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  function statusDot(lastSeen: string) {
    const ageMs = Date.now() - new Date(lastSeen).getTime()
    if (ageMs < 60_000) return { className: 'dot ok', title: 'seen <1m ago' }
    if (ageMs < 5 * 60_000) return { className: 'dot warn', title: `seen ${Math.floor(ageMs / 60_000)}m ago` }
    return { className: 'dot', title: `seen ${Math.floor(ageMs / 60_000)}m ago` }
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>lan-clients</span>
          </div>
          <h1 className="page-title">LAN clients</h1>
          <p className="page-sub">
            Hosts that have set a wirewarp gateway as their default route. Pin a host's egress to a tunnel
            attachment so its outbound traffic appears with that VPS's public IP — useful for WebRTC / SMTP
            / anything that wants a coherent public identity matching its inbound port forwards.
          </p>
        </div>
        <div className="page-actions">
          <span className="mono" style={{ fontSize: 12, color: 'var(--fg-2)' }}>
            {lan.length} discovered · {pinnedCount} pinned
          </span>
          <Button
            variant="primary"
            leading={<Ic.plus />}
            onClick={() => setShowAdd(true)}
            disabled={gatewayClients.length === 0}
            title={gatewayClients.length === 0 ? 'No gateway clients yet' : 'Manually register a LAN host'}
          >
            Add LAN client<span className="kbd-inline">N</span>
          </Button>
        </div>
      </div>

      <FilterBar
        filterRef={filterRef}
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'gateway',
            value: gatewayFilter,
            onChange: setGatewayFilter,
            options: [
              ['all', 'all'],
              ...gatewayClients.map((c) => [c.id, agentName(c.agent_id)] as [string, string]),
            ],
          },
          {
            label: 'pin',
            value: pinFilter,
            onChange: setPinFilter,
            options: [
              ['all', 'all'],
              ['pinned', 'pinned'],
              ['unpinned', 'unpinned'],
            ],
          },
          {
            label: 'activity',
            value: activityFilter,
            onChange: setActivityFilter,
            options: [
              ['all', 'all'],
              ['active', 'active <1m'],
              ['idle', 'idle'],
            ],
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{lan.length}
          </span>
        }
      />

      <div className="col" style={{ gap: 10 }}>
        {filtered.map((lc) => {
          const dot = statusDot(lc.last_seen)
          const gw = clients.find((c) => c.id === lc.tunnel_client_id)
          const pin = lc.egress_attachment_id ? attIndex.get(lc.egress_attachment_id) : null
          const hostForwards = forwardsByIp.get(lc.lan_ip) ?? []
          const symStats = hostForwards.map((pf) => symmetryFor(pf, lc))
          const asymCount = symStats.filter((s) => s === 'asymmetric').length

          return (
            <div key={lc.id} className="card">
              <div
                style={{
                  padding: 14,
                  display: 'grid',
                  gridTemplateColumns: '1fr auto',
                  gap: 12,
                  alignItems: 'start',
                }}
              >
                <div className="col" style={{ gap: 4, minWidth: 0 }}>
                  <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                    <span className={dot.className} title={dot.title}></span>
                    <span className="mono" style={{ fontSize: 14, fontWeight: 500 }}>
                      {lc.hostname || <span style={{ color: 'var(--fg-3)' }}>(unknown)</span>}
                    </span>
                    <IpChip ip={lc.lan_ip} />
                    <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                      {lc.mac || '—'}
                    </span>
                    {lc.egress_attachment_id && <Badge tone="peer">pinned</Badge>}
                    {asymCount > 0 && <Badge tone="warn">{asymCount} asymmetric forward{asymCount === 1 ? '' : 's'}</Badge>}
                  </div>
                  <div className="row" style={{ gap: 8, fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                    <span>via gateway {agentName(gw?.agent_id)}</span>
                    <span>·</span>
                    <span>seen {relTime(lc.last_seen)}</span>
                  </div>
                </div>
                <div className="row" style={{ gap: 4 }}>
                  <Button
                    size="sm"
                    variant="ghost"
                    leading={<Ic.edit />}
                    onClick={() => setMetaEditing(lc)}
                    title="Edit hostname / MAC"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    leading={<Ic.trash />}
                    onClick={() => {
                      if (confirm(`Drop ${lc.lan_ip} from the discovered list?`)) del.mutate(lc)
                    }}
                    disabled={del.isPending}
                    title="Drop from list (also clears egress pin)"
                  />
                </div>
              </div>

              <div
                style={{
                  borderTop: '1px solid var(--border-soft)',
                  padding: 14,
                  display: 'grid',
                  gridTemplateColumns: '180px 1fr',
                  gap: 14,
                  alignItems: 'start',
                }}
              >
                <span style={{ fontSize: 11, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                  Egress
                </span>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                  <Select
                    value={makeEgressValue(lc)}
                    onChange={(e) => setEgress.mutate({ lc, value: e.target.value })}
                    disabled={setEgress.isPending}
                  >
                    <option value="">home ISP (default)</option>
                    {gw?.attachments.flatMap((att) =>
                      attachmentOptions(att).map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      )),
                    )}
                  </Select>
                  {(() => {
                    const pinnedIp = lc.egress_tunnel_server_ip_id
                      ? pin?.server?.ips.find((i) => i.id === lc.egress_tunnel_server_ip_id)?.address
                      : pin?.server?.primary_ip
                    if (!pinnedIp) return null
                    return (
                      <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                        outbound appears as {pinnedIp}
                      </span>
                    )
                  })()}
                </div>
              </div>

              <div
                style={{
                  borderTop: '1px solid var(--border-soft)',
                  padding: 14,
                  display: 'grid',
                  gridTemplateColumns: '180px 1fr',
                  gap: 14,
                  alignItems: 'start',
                }}
              >
                <span style={{ fontSize: 11, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                  DNS records
                  {(lc.dns_record_ids?.length ?? 0) > 0 && (
                    <span className="mono" style={{ marginLeft: 6, color: 'var(--fg-3)' }}>
                      {lc.dns_record_ids?.length}
                    </span>
                  )}
                </span>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  {(lc.dns_record_ids?.length ?? 0) === 0 ? (
                    <span style={{ fontSize: 12, color: 'var(--fg-3)' }}>
                      {dnsConfigured
                        ? 'no records tracked — egress changes won\'t auto-update DNS'
                        : 'DNS sync provider not configured (Settings); records can still be listed here for documentation but won\'t auto-update'}
                    </span>
                  ) : (
                    lc.dns_record_ids!.map((r) => (
                      <Badge key={r.record_id} tone="info">
                        {r.name}
                      </Badge>
                    ))
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setDnsEditing(lc)}>
                    {(lc.dns_record_ids?.length ?? 0) === 0 ? 'configure' : 'edit'}
                  </Button>
                </div>
              </div>

              <div
                style={{
                  borderTop: '1px solid var(--border-soft)',
                  padding: 14,
                  display: 'grid',
                  gridTemplateColumns: '180px 1fr',
                  gap: 14,
                  alignItems: 'start',
                }}
              >
                <span style={{ fontSize: 11, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                  Port forwards
                  {hostForwards.length > 0 && (
                    <span className="mono" style={{ marginLeft: 6, color: 'var(--fg-3)' }}>
                      {hostForwards.length}
                    </span>
                  )}
                </span>
                <div className="col" style={{ gap: 4 }}>
                  {hostForwards.length === 0 ? (
                    <span style={{ fontSize: 12, color: 'var(--fg-3)' }}>no inbound forwards target this host</span>
                  ) : (
                    hostForwards.map((pf) => {
                      const lookup = attIndex.get(pf.attachment_id)
                      const sym = symmetryFor(pf, lc)
                      const ipForPf = lookup?.server?.ips.find((i) => i.id === pf.tunnel_server_ip_id)
                      const pubIP = ipForPf?.address || lookup?.server?.primary_ip || '*'
                      const pubPort = pf.public_port_end ? `${pf.public_port}-${pf.public_port_end}` : pf.public_port
                      const dstPort = pf.destination_port_end ? `${pf.destination_port}-${pf.destination_port_end}` : pf.destination_port
                      return (
                        <div
                          key={pf.id}
                          className="row"
                          style={{
                            gap: 8,
                            fontSize: 12,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--fg-1)',
                            flexWrap: 'wrap',
                          }}
                        >
                          <Badge tone={pf.protocol === 'tcp' ? 'info' : 'peer'}>{pf.protocol}</Badge>
                          <span>
                            {pubIP}:{pubPort}
                          </span>
                          <span style={{ color: 'var(--fg-3)' }}>→</span>
                          <span>
                            :{dstPort}
                          </span>
                          <span style={{ color: 'var(--fg-3)' }}>
                            via {agentName(lookup?.server?.agent_id)} ({lookup?.attachment.wg_interface})
                          </span>
                          {sym === 'symmetric' && <Badge tone="ok">↔ sym</Badge>}
                          {sym === 'asymmetric' && (
                            <>
                              <Badge tone="warn">⚠ asym</Badge>
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={fixSym.isPending}
                                onClick={() => fixSym.mutate({ pf, lc })}
                                title="Migrate this forward to match the host's egress pin"
                              >
                                fix
                              </Button>
                            </>
                          )}
                          {pf.description && (
                            <span style={{ color: 'var(--fg-3)' }}>· {pf.description}</span>
                          )}
                        </div>
                      )
                    })
                  )}
                </div>
              </div>
            </div>
          )
        })}
        {filtered.length === 0 && (
          <div className="empty">
            <div className="glyph">
              <Ic.host s={16} />
            </div>
            <h3>{lan.length === 0 ? 'No LAN clients discovered' : 'No clients match the filters'}</h3>
            {lan.length === 0 && (
              <p>
                Hosts on a gateway's LAN that route their egress through the gateway will appear here. Add the
                split-default routes <span className="mono">0.0.0.0/1 + 128.0.0.0/1 via &lt;gateway-ip&gt;</span>{' '}
                on the host so it forwards public-bound traffic through wirewarp.
              </p>
            )}
          </div>
        )}
      </div>

      {showAdd && (
        <AddLanClientDialog
          gatewayClients={gatewayClients}
          servers={servers}
          agents={agents}
          onClose={() => setShowAdd(false)}
        />
      )}
      {dnsEditing && (
        <ConfigureDnsDialog
          lc={dnsEditing}
          servers={servers}
          dnsConfigured={dnsConfigured}
          onClose={() => setDnsEditing(null)}
        />
      )}
      {metaEditing && (
        <EditLanClientMetaDialog
          lc={metaEditing}
          onClose={() => setMetaEditing(null)}
        />
      )}
    </div>
  )
}

function EditLanClientMetaDialog({
  lc,
  onClose,
}: {
  lc: LanClient
  onClose: () => void
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [hostname, setHostname] = useState(lc.hostname ?? '')
  const [mac, setMac] = useState(lc.mac ?? '')

  const save = useMutation({
    mutationFn: () =>
      lanApi.updateMeta(lc.tunnel_client_id, lc.id, {
        hostname: hostname.trim(),
        mac: mac.trim(),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients'] })
      push('LAN client updated', 'ok', 'lan://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'lan://'),
  })

  return (
    <Dialog
      title={`Edit ${lc.lan_ip}`}
      scheme="PATCH /tunnel-clients/.../lan-clients/..."
      onClose={onClose}
      width={480}
      footer={
        <>
          <span className="left" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
            Empty value clears the override and lets heartbeat re-discovery fill it.
          </span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? 'saving…' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Hostname">
          <Input
            mono
            placeholder="dev-docker"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="MAC">
          <Input
            mono
            placeholder="aa:bb:cc:dd:ee:ff"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
        </Field>
      </div>
    </Dialog>
  )
}

function AddLanClientDialog({
  gatewayClients,
  servers,
  agents,
  onClose,
}: {
  gatewayClients: TunnelClient[]
  servers: TunnelServer[]
  agents: { id: string; name: string; agent_id?: string }[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [gatewayId, setGatewayId] = useState(gatewayClients[0]?.id || '')
  const [lanIp, setLanIp] = useState('')
  const [hostname, setHostname] = useState('')
  const [mac, setMac] = useState('')
  // Composite value: `${attId}|${ipId}`. '' = home ISP.
  const [egressValue, setEgressValue] = useState('')

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  const selectedGw = gatewayClients.find((c) => c.id === gatewayId)
  const attachments = selectedGw?.attachments ?? []

  function attachmentOptions(att: TunnelClientAttachment): { value: string; label: string }[] {
    const s = servers.find((x) => x.id === att.tunnel_server_id)
    const name = s ? agentName(s.agent_id) : 'server'
    const ips = s?.ips ?? []
    if (ips.length === 0) {
      const pub = s?.primary_ip || s?.tunnel_network || '—'
      return [{ value: `${att.id}|`, label: `${pub} (${att.wg_interface} · ${name})` }]
    }
    return ips.map((ip) => ({
      value: `${att.id}|${ip.id}`,
      label: `${ip.address}${ip.is_primary ? ' · primary' : ''} (${att.wg_interface} · ${name})`,
    }))
  }

  const create = useMutation({
    mutationFn: () => {
      const { att, ip } = parseEgressValue(egressValue)
      return lanApi.create(gatewayId, {
        lan_ip: lanIp.trim(),
        hostname: hostname.trim() || undefined,
        mac: mac.trim() || undefined,
        egress_attachment_id: att,
        egress_tunnel_server_ip_id: ip,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients'] })
      push('LAN client added', 'ok', 'lan://')
      onClose()
    },
    onError: (e: Error) => {
      const msg = e.message
      if (msg.includes('409')) push('LAN client already registered on this gateway', 'err', 'lan://')
      else push(msg, 'err', 'lan://')
    },
  })

  // Lightweight IPv4 validation: four 0–255 dot-separated decimals.
  const ipOk = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(lanIp.trim())
  const parsedAtt = parseEgressValue(egressValue).att
  const ok = !!gatewayId && ipOk && (!parsedAtt || !!attachments.find((a) => a.id === parsedAtt))

  return (
    <Dialog
      title="Add LAN client"
      scheme="POST /tunnel-clients/.../lan-clients"
      onClose={onClose}
      width={560}
      footer={
        <>
          <span className="left" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
            Pre-registers a host before its first public-bound flow. Auto-discovery upserts on the same row.
          </span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!ok || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? 'adding…' : 'Add'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Gateway">
          <Select value={gatewayId} onChange={(e) => setGatewayId(e.target.value)}>
            {gatewayClients.map((c) => (
              <option key={c.id} value={c.id}>
                {agentName(c.agent_id)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="LAN IP" hint="The host's address on the gateway's LAN.">
          <Input
            mono
            placeholder="192.168.1.42"
            value={lanIp}
            onChange={(e) => setLanIp(e.target.value)}
            autoFocus
          />
        </Field>
        <div className="gridcols-2">
          <Field label="Hostname (optional)">
            <Input
              mono
              placeholder="dev-docker"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
          </Field>
          <Field label="MAC (optional)">
            <Input
              mono
              placeholder="aa:bb:cc:dd:ee:ff"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
            />
          </Field>
        </div>
        <Field label="Egress pin (optional)" hint="Choose now or leave home ISP and pin later.">
          <Select value={egressValue} onChange={(e) => setEgressValue(e.target.value)}>
            <option value="">home ISP (default)</option>
            {attachments.flatMap((att) =>
              attachmentOptions(att).map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              )),
            )}
          </Select>
        </Field>
      </div>
    </Dialog>
  )
}

function ConfigureDnsDialog({
  lc,
  servers,
  dnsConfigured,
  onClose,
}: {
  lc: LanClient
  servers: TunnelServer[]
  dnsConfigured: boolean
  onClose: () => void
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [zoneId, setZoneId] = useState('')
  const [selected, setSelected] = useState<DnsRecordRef[]>(lc.dns_record_ids ?? [])
  const [discovered, setDiscovered] = useState<(DnsRecordRef & { content: string })[]>([])

  const zonesQ = useQuery({
    queryKey: ['dns', 'zones'],
    queryFn: dnsApi.zones,
    enabled: dnsConfigured,
  })

  // Resolve the LAN client's currently active egress IP — that's the
  // value whose DNS records we want to "discover and track". Falls back
  // to the server's primary if no specific IP pin is set.
  const pinServer = lc.egress_attachment_id
    ? servers.find((s) => s.id === (servers.flatMap((x) => x.ips).find((i) => i.id === lc.egress_tunnel_server_ip_id) ? servers.flatMap((x) => x.ips).find((i) => i.id === lc.egress_tunnel_server_ip_id)!.tunnel_server_id : null))
    : null
  const pinIP = lc.egress_tunnel_server_ip_id
    ? servers.flatMap((s) => s.ips).find((i) => i.id === lc.egress_tunnel_server_ip_id)?.address
    : pinServer?.primary_ip

  const discover = useMutation({
    mutationFn: () => dnsApi.discover(zoneId, pinIP || ''),
    onSuccess: (rows) => {
      setDiscovered(
        rows.map((r) => ({ ...r, content: (r as DnsRecordRef & { content?: string }).content || '' })),
      )
      if (rows.length === 0) {
        push(`No A records in this zone point at ${pinIP}`, 'info', 'dns://')
      }
    },
    onError: (e: Error) => push(e.message, 'err', 'dns://'),
  })

  const save = useMutation({
    mutationFn: () =>
      lanApi.setDnsRecords(lc.tunnel_client_id, lc.id, selected.length ? selected : null),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients'] })
      push('DNS records saved', 'ok', 'dns://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'dns://'),
  })

  const toggle = (r: DnsRecordRef) => {
    setSelected((cur) =>
      cur.find((x) => x.record_id === r.record_id)
        ? cur.filter((x) => x.record_id !== r.record_id)
        : [...cur, { provider: r.provider, zone_id: r.zone_id, record_id: r.record_id, name: r.name }],
    )
  }

  return (
    <Dialog
      title={`DNS records for ${lc.hostname || lc.lan_ip}`}
      scheme="PATCH /tunnel-clients/.../lan-clients/.../dns_record_ids"
      onClose={onClose}
      width={640}
      footer={
        <>
          <span className="left" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
            {dnsConfigured
              ? 'Selected records will be re-pointed to the new egress IP every time it changes.'
              : 'DNS provider not configured. List records here for documentation; you\'ll get a manual-update notice when egress changes.'}
          </span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              disabled={save.isPending}
              onClick={() => save.mutate()}
            >
              {save.isPending ? 'saving…' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {!dnsConfigured && (
          <div
            style={{
              padding: 10,
              border: '1px solid var(--border)',
              borderRadius: 6,
              background: 'var(--bg-2)',
              fontSize: 12,
              color: 'var(--fg-2)',
            }}
          >
            DNS sync provider not configured. Set <span className="mono">dns_provider</span> +{' '}
            <span className="mono">cloudflare_api_token</span> on Settings to enable
            auto-update. Without it, this list is purely informational — you'll see a toast
            with the new IP and the records on every egress change so you can update them
            in your DNS UI.
          </div>
        )}

        {dnsConfigured && (
          <>
            <Field label="Zone" hint="Cloudflare zone hosting these records.">
              <Select value={zoneId} onChange={(e) => setZoneId(e.target.value)}>
                <option value="">— select zone —</option>
                {(zonesQ.data ?? []).map((z) => (
                  <option key={z.id} value={z.id}>
                    {z.name}
                  </option>
                ))}
              </Select>
            </Field>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <Button
                variant="primary"
                size="sm"
                disabled={!zoneId || !pinIP || discover.isPending}
                onClick={() => discover.mutate()}
                title={
                  pinIP
                    ? `Find A records pointing at ${pinIP}`
                    : 'Set an egress pin first to use discover'
                }
              >
                {discover.isPending ? 'scanning…' : `Discover records → ${pinIP || '(set egress first)'}`}
              </Button>
              <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                Or enter records manually below.
              </span>
            </div>
          </>
        )}

        {discovered.length > 0 && (
          <div className="col" style={{ gap: 4 }}>
            <span style={{ fontSize: 11, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Found
            </span>
            {discovered.map((r) => {
              const isSelected = !!selected.find((x) => x.record_id === r.record_id)
              return (
                <label
                  key={r.record_id}
                  style={{
                    display: 'flex',
                    gap: 8,
                    padding: '6px 8px',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    background: isSelected ? 'var(--peer-bg)' : 'var(--bg-2)',
                    cursor: 'pointer',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                  }}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggle(r)}
                  />
                  <span style={{ color: 'var(--fg-1)' }}>{r.name}</span>
                  <span style={{ color: 'var(--fg-3)', marginLeft: 'auto' }}>{r.content}</span>
                </label>
              )
            })}
          </div>
        )}

        {selected.length > 0 && (
          <div className="col" style={{ gap: 4 }}>
            <span style={{ fontSize: 11, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Tracking ({selected.length})
            </span>
            <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
              {selected.map((r) => (
                <Badge key={r.record_id} tone="info">
                  {r.name}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>
    </Dialog>
  )
}
