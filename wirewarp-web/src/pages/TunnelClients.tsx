import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  lanClients as lanApi,
  tunnelClients as tcApi,
  tunnelClientAttachments as tcaApi,
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
  StatusDot,
  Toggle,
  relTime,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import type { LanClient, TunnelClient, TunnelClientAttachment } from '../lib/types'

export default function TunnelClients() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState('')
  const [server, setServer] = useState('all')
  const [status, setStatus] = useState('all')
  const [editing, setEditing] = useState<TunnelClient | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)

  const clients = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []
  const servers = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  function serverLabel(serverId: string) {
    const s = servers.find((x) => x.id === serverId)
    return s ? agentName(s.agent_id) : serverId.slice(0, 8)
  }

  const filtered = useMemo(
    () =>
      clients.filter((c) => {
        if (server !== 'all' && !c.attachments.some((a) => a.tunnel_server_id === server))
          return false
        if (status !== 'all' && c.status !== status) return false
        if (filter) {
          const f = filter.toLowerCase()
          const a = agents.find((x) => x.id === c.agent_id)
          const candidates: (string | null | undefined)[] = [a?.name, c.lan_ip, c.id]
          for (const att of c.attachments) {
            candidates.push(att.tunnel_ip, att.wg_interface)
          }
          return candidates.filter(Boolean).some((x) => String(x).toLowerCase().includes(f))
        }
        return true
      }),
    [clients, agents, filter, server, status],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag !== 'INPUT' && e.key === '/') {
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
            <span>tunnel-clients</span>
          </div>
          <h1 className="page-title">Tunnel clients</h1>
          <p className="page-sub">Machines that dial out and become reachable via a server's public IP. One client may peer with multiple tunnel servers.</p>
        </div>
        <div className="page-actions">
          <Button variant="primary" leading={<Ic.plus />} onClick={() => navigate('/agents?new=1')}>
            Register client<span className="kbd-inline">N</span>
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
            value: server,
            onChange: setServer,
            options: [['all', 'all'], ...servers.map((s) => [s.id, agentName(s.agent_id)] as [string, string])],
          },
          {
            label: 'status',
            value: status,
            onChange: setStatus,
            options: [
              ['all', 'all'],
              ['online', 'online'],
              ['offline', 'offline'],
              ['connected', 'connected'],
              ['disconnected', 'disconnected'],
            ],
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{clients.length}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 24 }}></th>
              <th>Name</th>
              <th>Attachments</th>
              <th>LAN IP</th>
              <th>VM Network</th>
              <th>Gateway</th>
              <th>Created</th>
              <th style={{ width: 100, textAlign: 'right' }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => {
              const a = agents.find((x) => x.id === c.agent_id)
              return (
                <tr
                  key={c.id}
                  onClick={() => navigate(`/tunnel-clients/${c.id}`)}
                  style={{ cursor: 'pointer' }}
                >
                  <td data-label=""><StatusDot status={c.status} label={false} /></td>
                  <td data-label="agent">
                    <div className="row" style={{ gap: 6 }}>
                      <span className="tbl-link mono">{a?.name || c.id.slice(0, 8)}</span>
                      {c.is_gateway && <Badge tone="peer">gw</Badge>}
                    </div>
                  </td>
                  <td data-label="attachments" onClick={(e) => e.stopPropagation()}>
                    <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                      {c.attachments.length === 0 && (
                        <span style={{ color: 'var(--fg-3)' }}>—</span>
                      )}
                      {c.attachments.map((att) => (
                        <Badge key={att.id} tone="peer">
                          {serverLabel(att.tunnel_server_id)} · {att.tunnel_ip} · {att.wg_interface}
                        </Badge>
                      ))}
                      <Button
                        size="sm"
                        variant="ghost"
                        leading={<Ic.plus />}
                        onClick={() => setEditing(c)}
                      >
                        attach
                      </Button>
                    </div>
                  </td>
                  <td data-label="lan ip" className="mono">{c.lan_ip || <span style={{ color: 'var(--fg-3)' }}>—</span>}</td>
                  <td data-label="vm net" className="mono">{c.vm_network || <span style={{ color: 'var(--fg-3)' }}>—</span>}</td>
                  <td data-label="gateway">
                    {c.is_gateway ? <Badge tone="info">yes</Badge> : <span style={{ color: 'var(--fg-3)' }}>—</span>}
                  </td>
                  <td data-label="created" className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(c.created_at)}</td>
                  <td data-label="" onClick={(e) => e.stopPropagation()}>
                    <div className="row-actions">
                      <Button size="sm" variant="ghost" leading={<Ic.edit />} onClick={() => setEditing(c)}>
                        edit
                      </Button>
                    </div>
                  </td>
                </tr>
              )
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <div className="tbl-empty">
                    <h3>No tunnel clients</h3>
                    <p>Register a client agent. It will appear here once it phones home.</p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {editing && <EditClientDialog client={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function EditClientDialog({ client, onClose }: { client: TunnelClient; onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const servers = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []
  const [form, setForm] = useState({
    vm_network: client.vm_network || '',
    lan_ip: client.lan_ip || '',
    is_gateway: client.is_gateway,
  })
  const [attachServerId, setAttachServerId] = useState('')
  const [attachTunnelIp, setAttachTunnelIp] = useState('')

  const update = useMutation({
    mutationFn: () =>
      tcApi.update(client.id, {
        vm_network: form.vm_network,
        lan_ip: form.lan_ip,
        is_gateway: form.is_gateway,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
      push('client updated', 'ok', 'tc://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'tc://'),
  })
  const del = useMutation({
    mutationFn: () => tcApi.del(client.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
      push('client deleted', 'err', 'tc://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'tc://'),
  })

  const attach = useMutation({
    mutationFn: () =>
      tcaApi.create({
        tunnel_client_id: client.id,
        tunnel_server_id: attachServerId,
        tunnel_ip: attachTunnelIp || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
      qc.invalidateQueries({ queryKey: ['tunnel-client-attachments'] })
      setAttachServerId('')
      setAttachTunnelIp('')
      push('attached', 'ok', 'tca://')
    },
    onError: (e: Error) => push(e.message, 'err', 'tca://'),
  })

  const detach = useMutation({
    mutationFn: (att: TunnelClientAttachment) => tcaApi.del(att.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
      qc.invalidateQueries({ queryKey: ['tunnel-client-attachments'] })
      push('detached', 'ok', 'tca://')
    },
    onError: (e: Error) => push(e.message, 'err', 'tca://'),
  })

  function agentName(id?: string | null) {
    if (!id) return '—'
    return agents.find((a) => a.id === id)?.name || id.slice(0, 8)
  }

  const attachedServerIds = new Set(client.attachments.map((a) => a.tunnel_server_id))
  const availableServers = servers.filter((s) => !attachedServerIds.has(s.id))

  return (
    <Dialog
      title="Edit tunnel client"
      scheme={`PATCH /tunnel-clients/${client.id.slice(0, 8)}`}
      onClose={onClose}
      width={680}
      footer={
        <>
          <Button
            variant="danger"
            leading={<Ic.trash />}
            onClick={() => {
              if (confirm('Delete this tunnel client?')) del.mutate()
            }}
          >
            delete
          </Button>
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
        <Field label="Gateway" hint="Routes inbound DNAT'd traffic to LAN">
          <div className="row">
            <Toggle on={form.is_gateway} onChange={(v) => setForm({ ...form, is_gateway: v })} />
            <span style={{ fontSize: 12, color: 'var(--fg-2)' }}>{form.is_gateway ? 'yes' : 'no'}</span>
          </div>
        </Field>
        <div></div>
        {form.is_gateway && (
          <>
            <Field label="LAN network">
              <Input
                mono
                placeholder="192.168.1.0/24"
                value={form.vm_network}
                onChange={(e) => setForm({ ...form, vm_network: e.target.value })}
              />
            </Field>
            <Field label="LAN IP">
              <Input
                mono
                placeholder="192.168.1.10"
                value={form.lan_ip}
                onChange={(e) => setForm({ ...form, lan_ip: e.target.value })}
              />
            </Field>
          </>
        )}
      </div>

      <div style={{ marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Attachments
          </span>
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
            {client.attachments.length} peering{client.attachments.length === 1 ? '' : 's'}
          </span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {client.attachments.map((att) => (
            <div
              key={att.id}
              className="row"
              style={{
                justifyContent: 'space-between',
                background: 'var(--bg-2)',
                padding: '6px 10px',
                borderRadius: 6,
                border: '1px solid var(--border)',
              }}
            >
              <div className="row" style={{ gap: 8 }}>
                <Badge tone="peer">{att.wg_interface}</Badge>
                <span className="mono" style={{ fontSize: 12 }}>
                  {agentName(servers.find((s) => s.id === att.tunnel_server_id)?.agent_id)}
                </span>
                <IpChip ip={att.tunnel_ip} />
                <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                  fwmark 0x{att.fwmark.toString(16)} · table {att.route_table_id}
                </span>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  if (confirm(`Detach ${att.wg_interface} (${att.tunnel_ip})?`)) detach.mutate(att)
                }}
                disabled={detach.isPending}
              >
                detach
              </Button>
            </div>
          ))}
          {client.attachments.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--fg-3)' }}>No attachments yet — add one below.</div>
          )}
        </div>

        <div className="gridcols-2" style={{ marginTop: 12 }}>
          <Field label="Attach to server">
            <Select value={attachServerId} onChange={(e) => setAttachServerId(e.target.value)}>
              <option value="">— select —</option>
              {availableServers.map((s) => (
                <option key={s.id} value={s.id}>
                  {agentName(s.agent_id)} ({s.primary_ip || s.tunnel_network})
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Tunnel IP" hint="Leave blank to auto-allocate">
            <div className="row" style={{ gap: 6 }}>
              <Input
                mono
                placeholder="auto"
                value={attachTunnelIp}
                onChange={(e) => setAttachTunnelIp(e.target.value)}
              />
              <Button
                size="sm"
                variant="primary"
                disabled={!attachServerId || attach.isPending}
                onClick={() => attach.mutate()}
              >
                {attach.isPending ? 'attaching…' : 'attach'}
              </Button>
            </div>
          </Field>
        </div>
      </div>

      {client.is_gateway && (
        <LanClientsSection client={client} attachments={client.attachments} servers={servers} agents={agents} />
      )}
    </Dialog>
  )
}

function LanClientsSection({
  client,
  attachments,
  servers,
  agents,
}: {
  client: TunnelClient
  attachments: TunnelClientAttachment[]
  servers: Awaited<ReturnType<typeof tsApi.list>>
  agents: Awaited<ReturnType<typeof agentsApi.list>>
}) {
  const qc = useQueryClient()
  const push = useToast()
  const lanQ = useQuery({
    queryKey: ['lan-clients', client.id],
    queryFn: () => lanApi.list(client.id),
    
  })
  const lanList = lanQ.data ?? []
  const pinnedCount = lanList.filter((c) => c.egress_attachment_id).length

  const setEgress = useMutation({
    mutationFn: (vars: { lc: LanClient; value: string }) => {
      const v = vars.value
      if (!v) return lanApi.setEgress(client.id, vars.lc.id, null, null)
      const [att, ip] = v.split('|')
      return lanApi.setEgress(client.id, vars.lc.id, att || null, ip || null)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients', client.id] })
      push('egress updated', 'ok', 'lan://')
    },
    onError: (e: Error) => push(e.message, 'err', 'lan://'),
  })

  const del = useMutation({
    mutationFn: (lc: LanClient) => lanApi.del(client.id, lc.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lan-clients', client.id] })
    },
    onError: (e: Error) => push(e.message, 'err', 'lan://'),
  })

  function attachmentOptions(att: TunnelClientAttachment): { value: string; label: string }[] {
    const s = servers.find((x) => x.id === att.tunnel_server_id)
    const name = s ? agents.find((a) => a.id === s.agent_id)?.name || s.id.slice(0, 8) : 'server'
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

  function lcEgressValue(lc: LanClient): string {
    if (!lc.egress_attachment_id) return ''
    return `${lc.egress_attachment_id}|${lc.egress_tunnel_server_ip_id || ''}`
  }

  function statusDot(lastSeen: string) {
    const ageMs = Date.now() - new Date(lastSeen).getTime()
    if (ageMs < 60_000) return { className: 'dot ok', title: 'seen <1m ago' }
    if (ageMs < 5 * 60_000) return { className: 'dot warn', title: `seen ${Math.floor(ageMs / 60_000)}m ago` }
    return { className: 'dot', title: `seen ${Math.floor(ageMs / 60_000)}m ago` }
  }

  return (
    <div style={{ marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 12, color: 'var(--fg-2)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
          LAN clients
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
          {lanList.length} detected{pinnedCount > 0 ? ` · ${pinnedCount} pinned` : ''}
        </span>
      </div>
      {lanList.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--fg-3)' }}>
          No LAN hosts detected forwarding through this gateway yet. Hosts that set this gateway as their default route (or add the split-default routes) will appear here within a heartbeat (~30s).
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {lanList.map((lc) => {
            const dot = statusDot(lc.last_seen)
            const pinned = !!lc.egress_attachment_id
            return (
              <div
                key={lc.id}
                style={{
                  background: 'var(--bg-2)',
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <div className="row" style={{ gap: 8 }}>
                    <span className={dot.className} title={dot.title}></span>
                    <span className="mono" style={{ fontSize: 13 }}>
                      {lc.hostname || <span style={{ color: 'var(--fg-3)' }}>(unknown)</span>}
                    </span>
                    <IpChip ip={lc.lan_ip} />
                    <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                      {lc.mac || '—'}
                    </span>
                    {pinned && <Badge tone="peer">pinned</Badge>}
                  </div>
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
                <div className="row" style={{ gap: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>Egress</span>
                  <Select
                    value={lcEgressValue(lc)}
                    onChange={(e) => setEgress.mutate({ lc, value: e.target.value })}
                    disabled={setEgress.isPending}
                  >
                    <option value="">home ISP (default)</option>
                    {attachments.flatMap((att) =>
                      attachmentOptions(att).map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      )),
                    )}
                  </Select>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
