import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  tunnelServers as tsApi,
  tunnelServerIPs as ipApi,
  portForwards as pfApi,
  tunnelClients as tcApi,
} from '../lib/api'
import {
  Badge,
  Button,
  Dialog,
  Field,
  FilterBar,
  IpChip,
  Input,
  Stat,
  StatusDot,
  Toggle,
  Tooltip,
  relTime,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import type { TunnelServer, TunnelServerIP } from '../lib/types'

export default function TunnelServers() {
  const navigate = useNavigate()
  const location = useLocation()
  const [filter, setFilter] = useState('')
  const [editing, setEditing] = useState<TunnelServer | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)

  const serversQ = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list })
  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list })
  const servers = serversQ.data ?? []
  const agents = agentsQ.data ?? []

  const totalIps = servers.reduce((s, t) => s + (t.ips?.length || 0), 0)

  function agentName(id: string) {
    return agents.find((x) => x.id === id)?.name || id.slice(0, 8)
  }

  const filtered = servers.filter((s) => {
    if (!filter) return true
    const f = filter.toLowerCase()
    const a = agents.find((x) => x.id === s.agent_id)
    return [a?.name, s.primary_ip, s.tunnel_network, s.id]
      .filter(Boolean)
      .some((x) => x!.toLowerCase().includes(f))
  })

  // Anchor scroll on mount/hash change: #ts_<id>
  useEffect(() => {
    if (!location.hash) return
    const id = location.hash.replace(/^#/, '')
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      el.classList.add('focused-card')
      setTimeout(() => el.classList.remove('focused-card'), 1600)
    }
  }, [location.hash, servers])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag === 'INPUT') return
      if (e.key === '/') {
        e.preventDefault()
        filterRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>tunnel-servers</span>
          </div>
          <h1 className="page-title">Tunnel servers</h1>
          <p className="page-sub">VPSes with public IPs that act as ingress for your mesh.</p>
        </div>
        <div className="page-actions">
          <Button variant="primary" leading={<Ic.plus />} onClick={() => navigate('/agents?new=1')}>
            Register server<span className="kbd-inline">N</span>
          </Button>
        </div>
      </div>

      <FilterBar
        filterRef={filterRef}
        filter={filter}
        setFilter={setFilter}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length} servers · {totalIps} ips
          </span>
        }
      />

      <div className="col" style={{ gap: 12 }}>
        {filtered.map((s) => (
          <ServerCard
            key={s.id}
            server={s}
            agentName={agentName(s.agent_id)}
            agentStatus={agents.find((x) => x.id === s.agent_id)?.status}
            onEdit={() => setEditing(s)}
          />
        ))}
        {filtered.length === 0 && (
          <div className="empty">
            <div className="glyph">
              <Ic.server s={16} />
            </div>
            <h3>No tunnel servers</h3>
            <p>Register a server agent (VPS with public IP) to get started.</p>
            <Button variant="primary" leading={<Ic.plus />} onClick={() => navigate('/agents?new=1')}>
              Register server
            </Button>
          </div>
        )}
      </div>

      {editing && <EditServerDialog server={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function ServerCard({
  server,
  agentName,
  agentStatus,
  onEdit,
}: {
  server: TunnelServer
  agentName: string
  agentStatus?: string
  onEdit: () => void
}) {
  const navigate = useNavigate()
  const ipsQ = useQuery({
    queryKey: ['tunnel-server-ips', server.id],
    queryFn: () => ipApi.list(server.id),
  })
  const clientsQ = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list })
  const pfQ = useQuery({ queryKey: ['port-forwards'], queryFn: () => pfApi.list() })
  const ips = ipsQ.data ?? server.ips ?? []
  const clients = (clientsQ.data ?? []).filter((c) =>
    c.attachments.some((a) => a.tunnel_server_id === server.id),
  )
  const onlineClients = clients.filter((c) => c.status === 'online' || c.status === 'connected').length
  const attachmentIdsForServer = new Set<string>(
    (clientsQ.data ?? []).flatMap((c) =>
      c.attachments.filter((a) => a.tunnel_server_id === server.id).map((a) => a.id),
    ),
  )
  const forwards = (pfQ.data ?? []).filter((p) => attachmentIdsForServer.has(p.attachment_id))
  const [adding, setAdding] = useState(false)

  return (
    <div id={`ts_${server.id}`} className="card">
      <div className="card-head">
        <div className="title">
          <StatusDot status={agentStatus || 'disconnected'} label={false} />
          <span className="mono">{agentName}</span>
          <span className="scheme">/ {server.id.slice(0, 12)}</span>
        </div>
        <div className="row">
          <Button size="sm" variant="ghost" leading={<Ic.edit />} onClick={onEdit}>
            edit
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => navigate(`/tunnel-servers/${server.id}`)}
          >
            details <Ic.arrow />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => navigate(`/agents/${server.agent_id}`)}
          >
            open agent <Ic.arrow />
          </Button>
        </div>
      </div>
      <div className="server-stat-grid">
        <Stat label="wg interface" value={`${server.wg_interface}:${server.wg_port}`} />
        <Stat label="network" value={server.tunnel_network} />
        <Stat label="clients" value={`${onlineClients}/${clients.length}`} />
        <Stat label="port forwards" value={String(forwards.length)} />
      </div>
      <div style={{ padding: 14 }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 8,
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: 'var(--fg-2)',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: 0.5,
            }}
          >
            Public IPs
          </span>
          <Button size="sm" variant="ghost" leading={<Ic.plus />} onClick={() => setAdding(true)}>
            add ip
          </Button>
        </div>
        {ips.length === 0 && (
          <p style={{ fontSize: 12, color: 'var(--fg-3)' }}>
            No IPs yet. The agent's heartbeat adds the first one automatically.
          </p>
        )}
        {ips.length > 0 && <IPTable ips={ips} serverId={server.id} />}
      </div>
      {adding && (
        <AddIpDialog
          serverId={server.id}
          existingPrimary={ips.some((ip) => ip.is_primary)}
          onClose={() => setAdding(false)}
        />
      )}
    </div>
  )
}

function IPTable({ ips, serverId }: { ips: TunnelServerIP[]; serverId: string }) {
  const qc = useQueryClient()
  const push = useToast()

  function invalidate() {
    qc.invalidateQueries({ queryKey: ['tunnel-server-ips', serverId] })
    qc.invalidateQueries({ queryKey: ['tunnel-servers'] })
  }

  const setPrimary = useMutation({
    mutationFn: (id: string) => ipApi.update(id, { is_primary: true }),
    onSuccess: () => {
      invalidate()
      push('primary IP updated', 'ok', 'ts://')
    },
    onError: (e: Error) => push(e.message, 'err', 'ts://'),
  })
  const del = useMutation({
    mutationFn: ipApi.del,
    onSuccess: () => {
      invalidate()
      push('IP removed', 'ok', 'ts://')
    },
    onError: (e: Error) => push(e.message, 'err', 'ts://'),
  })

  return (
    <div className="tbl-hscroll">
      <table className="tbl tbl-keep" style={{ tableLayout: 'fixed' }}>
        <thead>
          <tr>
            <th style={{ width: 24 }}></th>
            <th style={{ width: 220 }}>Address</th>
            <th style={{ width: 160 }}>Label</th>
            <th style={{ width: 100 }}>Forwards</th>
            <th>Created</th>
            <th style={{ width: 200, textAlign: 'right' }}></th>
          </tr>
        </thead>
        <tbody>
          {ips.map((ip) => (
            <tr key={ip.id}>
              <td>
                {ip.is_primary ? (
                  <Tooltip text="primary">
                    <span className="dot ok"></span>
                  </Tooltip>
                ) : (
                  <span className="dot"></span>
                )}
              </td>
              <td>
                <IpChip ip={ip.address} primary={ip.is_primary} />
              </td>
              <td className="mono" style={{ color: 'var(--fg-1)' }}>
                {ip.label || '—'}
              </td>
              <td className="mono">{ip.port_forward_count}</td>
              <td className="mono" style={{ color: 'var(--fg-2)' }}>
                {relTime(ip.created_at)}
              </td>
              <td>
                <div className="row-actions">
                  {!ip.is_primary && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setPrimary.mutate(ip.id)}
                      disabled={setPrimary.isPending}
                    >
                      set primary
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    leading={<Ic.trash />}
                    style={{ color: 'var(--err)' }}
                    disabled={ip.port_forward_count > 0}
                    title={
                      ip.port_forward_count > 0
                        ? `${ip.port_forward_count} forward(s) bound — delete those first`
                        : 'Delete'
                    }
                    onClick={() => {
                      if (confirm(`Delete IP ${ip.address}?`)) del.mutate(ip.id)
                    }}
                  >
                    delete
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AddIpDialog({
  serverId,
  existingPrimary,
  onClose,
}: {
  serverId: string
  existingPrimary: boolean
  onClose: () => void
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [address, setAddress] = useState('')
  const [label, setLabel] = useState('')
  const [primary, setPrimary] = useState(!existingPrimary)
  const create = useMutation({
    mutationFn: () =>
      ipApi.create({
        tunnel_server_id: serverId,
        address,
        label: label || null,
        is_primary: primary,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-server-ips', serverId] })
      qc.invalidateQueries({ queryKey: ['tunnel-servers'] })
      push('IP added', 'ok', 'ts://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'ts://'),
  })

  return (
    <Dialog
      title="Add public IP"
      scheme="POST /tunnel-server-ips"
      onClose={onClose}
      width={520}
      footer={
        <>
          <span className="left">First IP for a server is auto-promoted to primary.</span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!address || create.isPending}
              onClick={() => create.mutate()}
            >
              {create.isPending ? 'adding…' : 'Add IP'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Address" hint="IPv4 address routable to this server.">
          <Input mono placeholder="e.g. 185.213.44.21" value={address} onChange={(e) => setAddress(e.target.value)} autoFocus />
        </Field>
        <Field label="Label (optional)">
          <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. ddos-protected" />
        </Field>
        <Field label="Primary">
          <div className="row">
            <Toggle on={primary} onChange={setPrimary} />
            <span style={{ fontSize: 12, color: 'var(--fg-2)' }}>
              {primary ? 'will be the primary endpoint' : 'secondary IP'}
            </span>
          </div>
        </Field>
      </div>
    </Dialog>
  )
}

function EditServerDialog({ server, onClose }: { server: TunnelServer; onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const [wgPort, setWgPort] = useState(server.wg_port)
  const [iface, setIface] = useState(server.public_iface)
  const [showRebase, setShowRebase] = useState(false)

  const update = useMutation({
    mutationFn: () =>
      tsApi.update(server.id, {
        wg_port: wgPort,
        public_iface: iface,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-servers'] })
      push('server updated', 'ok', 'ts://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'ts://'),
  })

  return (
    <>
      <Dialog
        title="Edit tunnel server"
        scheme={`PATCH /tunnel-servers/${server.id.slice(0, 8)}`}
        onClose={onClose}
        width={620}
        footer={
          <>
            <span className="left">Configured servers require an explicit host teardown before removal.</span>
            <div className="right">
              <Button variant="ghost" onClick={onClose}>Cancel</Button>
              <Button variant="primary" onClick={() => update.mutate()} disabled={update.isPending}>
                {update.isPending ? 'saving…' : 'Save'}
              </Button>
            </div>
          </>
        }
      >
        <div className="gridcols-2">
          <Field label="WG interface">
            <Input mono value={server.wg_interface} disabled />
          </Field>
          <Field label="WG port">
            <Input mono type="number" value={wgPort} onChange={(e) => setWgPort(parseInt(e.target.value, 10) || 0)} />
          </Field>
          <Field label="Public iface">
            <Input mono value={iface} onChange={(e) => setIface(e.target.value)} />
          </Field>
          <Field label="Tunnel network" hint="Use 'rebase' to change — it renumbers clients & forwards.">
            <div className="row" style={{ gap: 6 }}>
              <Input mono value={server.tunnel_network} disabled style={{ flex: 1 }} />
              <Button size="sm" variant="ghost" onClick={() => setShowRebase(true)}>
                rebase…
              </Button>
            </div>
          </Field>
          <Field label="Public key">
            <Input mono value={server.wg_public_key || '(not set)'} disabled />
          </Field>
          <Field label="Primary IP">
            <Input mono value={server.primary_ip || '—'} disabled />
          </Field>
        </div>
        <div style={{ marginTop: 12, fontSize: 12, color: 'var(--fg-3)' }}>
          Public key & primary IP are managed via the agent and the IP table.
        </div>
        {server && <Badge tone="neutral">id: {server.id}</Badge>}
      </Dialog>
      {showRebase && (
        <RebaseDialog
          server={server}
          onClose={() => setShowRebase(false)}
          onDone={onClose}
        />
      )}
    </>
  )
}

function RebaseDialog({
  server,
  onClose,
  onDone,
}: {
  server: TunnelServer
  onClose: () => void
  onDone: () => void
}) {
  const qc = useQueryClient()
  const push = useToast()
  const [network, setNetwork] = useState('')

  const suggestQ = useQuery({
    queryKey: ['tunnel-servers', server.id, 'rebase-suggestion'],
    queryFn: () => tsApi.rebaseSuggestion(server.id),
  })

  useEffect(() => {
    if (!network && suggestQ.data) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNetwork(suggestQ.data.tunnel_network)
    }
  }, [suggestQ.data, network])

  const rebase = useMutation({
    mutationFn: () => tsApi.rebase(server.id, network),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-servers'] })
      qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
      qc.invalidateQueries({ queryKey: ['port-forwards'] })
      push(`network rebased to ${network}`, 'ok', 'ts://')
      onClose()
      onDone()
    },
    onError: (e: Error) => push(e.message, 'err', 'ts://'),
  })

  function go() {
    if (!confirm(
      `Rebase ${server.tunnel_network} → ${network}? Every client on this server will reconfigure (brief WG re-handshake) and iptables forwards will be re-added against the new destination IPs.`
    )) return
    rebase.mutate()
  }

  return (
    <Dialog
      title="Rebase tunnel network"
      scheme={`POST /tunnel-servers/${server.id.slice(0, 8)}/rebase`}
      onClose={onClose}
      width={520}
      footer={
        <>
          <span className="left">Renumbers clients & forwards. Disruptive but quick.</span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!network || rebase.isPending || network === server.tunnel_network}
              onClick={go}
            >
              {rebase.isPending ? 'rebasing…' : 'Rebase'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Current network">
          <Input mono value={server.tunnel_network} disabled />
        </Field>
        <Field label="New network" hint="Must be an IPv4 /24. Suggestion is the next free /24 in the pool.">
          <Input
            mono
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
            placeholder={suggestQ.isLoading ? 'loading suggestion…' : '10.21.0.0/24'}
            autoFocus
          />
        </Field>
      </div>
    </Dialog>
  )
}
