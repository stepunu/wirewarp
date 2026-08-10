import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  tunnelServerIPs as ipApi,
  tunnelServers as tsApi,
} from '../lib/api'
import type { Node, TunnelServerIP, TunnelServerSummary } from '../lib/types'
import { useRole } from '../hooks/useRole'
import { useToast } from './Toasts'
import { Badge, Button, Dialog, Field, Input, Toggle, relTime } from './ui'
import { Ic } from './icons'

export function NodeLifecycleActions({ node }: { node: Node }) {
  const push = useToast()
  const { canMutate, isAdmin } = useRole()
  const [jwt, setJwt] = useState<string | null>(null)

  const update = useMutation({
    mutationFn: () => agentsApi.update(node.agent_id),
    onSuccess: () => push('agent update queued', 'ok', 'agent://'),
    onError: (error: Error) => push(error.message, 'err', 'agent://'),
  })
  const issueJwt = useMutation({
    mutationFn: () => agentsApi.issueJwt(node.agent_id),
    onSuccess: (data) => setJwt(data.jwt),
    onError: (error: Error) => push(error.message, 'err', 'agent://'),
  })

  if (!canMutate) return null
  return (
    <>
      <div className="page-actions">
        {isAdmin && (
          <Button size="sm" onClick={() => issueJwt.mutate()} disabled={issueJwt.isPending}>
            {issueJwt.isPending ? 'issuing...' : 'reissue JWT'}
          </Button>
        )}
        <Button
          size="sm"
          variant="primary"
          onClick={() => update.mutate()}
          disabled={update.isPending || node.status !== 'connected'}
          title={node.status !== 'connected' ? 'Agent must be connected.' : ''}
        >
          {update.isPending ? 'updating...' : 'update agent'}
        </Button>
      </div>
      {jwt && <AgentJwtDialog jwt={jwt} onClose={() => setJwt(null)} />}
    </>
  )
}

function AgentJwtDialog({ jwt, onClose }: { jwt: string; onClose: () => void }) {
  const push = useToast()
  const command = `sudo sed -i "s|^agent_jwt:.*|agent_jwt: ${jwt}|" /etc/wirewarp/agent.yaml\nsudo systemctl restart wirewarp-agent`
  return (
    <Dialog
      title="New agent JWT"
      scheme="POST /agents/{id}/issue-jwt"
      onClose={onClose}
      width={680}
      footer={
        <>
          <span className="left">JWT shown once.</span>
          <div className="right"><Button onClick={onClose}>Close</Button></div>
        </>
      }
    >
      <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--fg-2)' }}>
        Apply this value on the agent machine. The agent reconnects without changing WireGuard state.
      </div>
      <div className="field-label" style={{ marginBottom: 4 }}>JWT</div>
      <pre className="code" style={{ marginBottom: 8 }}>{jwt}</pre>
      <Button
        size="sm"
        variant="ghost"
        leading={<Ic.copy />}
        onClick={() => {
          navigator.clipboard.writeText(jwt)
          push('JWT copied', 'ok', 'clip://')
        }}
      >
        copy JWT
      </Button>
      <div className="field-label" style={{ marginTop: 14, marginBottom: 4 }}>Apply</div>
      <pre className="code">{command}</pre>
      <Button
        size="sm"
        variant="ghost"
        leading={<Ic.copy />}
        onClick={() => {
          navigator.clipboard.writeText(command)
          push('command copied', 'ok', 'clip://')
        }}
      >
        copy command
      </Button>
    </Dialog>
  )
}

export function ServerConfigurationPanel({
  server,
  loading = false,
  error,
}: {
  server?: TunnelServerSummary
  loading?: boolean
  error?: Error | null
}) {
  if (error) {
    return <div className="card"><div className="card-body" style={{ color: 'var(--err)' }}>Could not load server configuration: {error.message}</div></div>
  }
  if (!server) {
    return <div className="card"><div className="card-body">{loading ? 'Loading server configuration...' : 'Server configuration is not available.'}</div></div>
  }
  return (
    <ServerConfigurationEditor
      key={`${server.id}:${server.wg_port}:${server.public_iface}`}
      server={server}
    />
  )
}

function ServerConfigurationEditor({ server }: { server: TunnelServerSummary }) {
  const qc = useQueryClient()
  const push = useToast()
  const { canMutate } = useRole()
  const [wgPort, setWgPort] = useState(server.wg_port)
  const [publicIface, setPublicIface] = useState(server.public_iface)
  const [showAddIp, setShowAddIp] = useState(false)

  const ipsQ = useQuery({
    queryKey: ['tunnel-server-ips', server.id],
    queryFn: () => ipApi.list(server.id),
  })
  const ips = ipsQ.data ?? server.ips
  const settingsInvalid = wgPort < 1 || wgPort > 65535 || !publicIface.trim()

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['nodes'] })
    qc.invalidateQueries({ queryKey: ['tunnel-servers'] })
    qc.invalidateQueries({ queryKey: ['tunnel-server-summary', server.id] })
    qc.invalidateQueries({ queryKey: ['tunnel-server-ips', server.id] })
    qc.invalidateQueries({ queryKey: ['tunnel-clients'] })
    qc.invalidateQueries({ queryKey: ['tunnel-client-summary'] })
    qc.invalidateQueries({ queryKey: ['tunnel-client-attachments'] })
    qc.invalidateQueries({ queryKey: ['port-forwards'] })
  }
  const update = useMutation({
    mutationFn: () => tsApi.update(server.id, { wg_port: wgPort, public_iface: publicIface }),
    onSuccess: () => {
      refresh()
      push('server configuration saved', 'ok', 'ts://')
    },
    onError: (error: Error) => push(error.message, 'err', 'ts://'),
  })
  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Tunnel server configuration</div>
            <div className="scheme">WireGuard listener and public interface</div>
          </div>
          {canMutate && (
            <Button size="sm" variant="primary" disabled={update.isPending || settingsInvalid} onClick={() => update.mutate()}>
              {update.isPending ? 'saving...' : 'Save settings'}
            </Button>
          )}
        </div>
        <div className="card-body">
          <div className="gridcols-2">
            <Field label="WireGuard interface"><Input mono value={server.wg_interface} disabled /></Field>
            <Field label="WireGuard port">
              <Input
                mono
                type="number"
                min={1}
                max={65535}
                value={wgPort}
                disabled={!canMutate}
                onChange={(event) => setWgPort(Number(event.target.value))}
              />
            </Field>
            <Field label="Public interface">
              <Input mono value={publicIface} disabled={!canMutate} onChange={(event) => setPublicIface(event.target.value)} />
            </Field>
            <Field label="Primary IP"><Input mono value={server.primary_ip || 'not set'} disabled /></Field>
            <Field label="Tunnel network" hint="Network rebases require acknowledged teardown support.">
              <Input mono value={server.tunnel_network} disabled />
            </Field>
            <Field label="Public key"><Input mono value={server.wg_public_key || 'not set'} disabled /></Field>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <div>
            <div className="title">Public IPs</div>
            <div className="scheme">{ips.length} address{ips.length === 1 ? '' : 'es'}</div>
          </div>
          {canMutate && <Button size="sm" variant="ghost" leading={<Ic.plus />} onClick={() => setShowAddIp(true)}>add IP</Button>}
        </div>
        <ServerIpTable ips={ips} canMutate={canMutate} onChanged={refresh} />
        {ipsQ.isError && (
          <div className="card-body" style={{ color: 'var(--err)', fontSize: 12 }}>
            Could not refresh public IPs: {ipsQ.error.message}
          </div>
        )}
      </div>

      {showAddIp && (
        <AddServerIpDialog
          serverId={server.id}
          existingPrimary={ips.some((ip) => ip.is_primary)}
          onChanged={refresh}
          onClose={() => setShowAddIp(false)}
        />
      )}
    </div>
  )
}

function ServerIpTable({
  ips,
  canMutate,
  onChanged,
}: {
  ips: TunnelServerIP[]
  canMutate: boolean
  onChanged: () => void
}) {
  const push = useToast()
  const setPrimary = useMutation({
    mutationFn: (id: string) => ipApi.update(id, { is_primary: true }),
    onSuccess: () => {
      onChanged()
      push('primary IP updated', 'ok', 'ts://')
    },
    onError: (error: Error) => push(error.message, 'err', 'ts://'),
  })
  const remove = useMutation({
    mutationFn: (id: string) => ipApi.del(id),
    onSuccess: () => {
      onChanged()
      push('IP removed', 'ok', 'ts://')
    },
    onError: (error: Error) => push(error.message, 'err', 'ts://'),
  })

  return (
    <div className="tbl-hscroll">
      <table className="tbl tbl-keep">
        <thead><tr><th>Address</th><th>Label</th><th>Forwards</th><th>Egress pins</th><th>Created</th>{canMutate && <th />}</tr></thead>
        <tbody>
          {ips.length === 0 && (
            <tr><td colSpan={canMutate ? 6 : 5}><div className="tbl-empty"><h3>No public IPs</h3></div></td></tr>
          )}
          {ips.map((ip) => (
            <tr key={ip.id}>
              <td className="mono">
                <span className={`dot ${ip.is_primary ? 'ok' : ''}`} style={{ marginRight: 8 }} />
                {ip.address} {ip.is_primary && <Badge tone="ok">primary</Badge>}
              </td>
              <td>{ip.label || '-'}</td>
              <td className="mono">{ip.port_forward_count}</td>
              <td className="mono">{ip.lan_egress_pin_count}</td>
              <td className="mono">{relTime(ip.created_at)}</td>
              {canMutate && (
                <td>
                  <div className="row-actions">
                    {!ip.is_primary && (
                      <Button size="sm" variant="ghost" disabled={setPrimary.isPending} onClick={() => setPrimary.mutate(ip.id)}>
                        set primary
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      leading={<Ic.trash />}
                      style={{ color: 'var(--err)' }}
                      disabled={remove.isPending || ip.port_forward_count > 0 || ip.lan_egress_pin_count > 0}
                      title={
                        ip.port_forward_count > 0
                          ? `Delete ${ip.port_forward_count} bound forward(s) first.`
                          : ip.lan_egress_pin_count > 0
                            ? `Move ${ip.lan_egress_pin_count} LAN egress pin(s) first.`
                            : 'Delete IP'
                      }
                      onClick={() => {
                        if (confirm(`Delete IP ${ip.address}?`)) remove.mutate(ip.id)
                      }}
                    >
                      delete
                    </Button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AddServerIpDialog({
  serverId,
  existingPrimary,
  onChanged,
  onClose,
}: {
  serverId: string
  existingPrimary: boolean
  onChanged: () => void
  onClose: () => void
}) {
  const push = useToast()
  const [address, setAddress] = useState('')
  const [label, setLabel] = useState('')
  const [primary, setPrimary] = useState(!existingPrimary)
  const create = useMutation({
    mutationFn: () => ipApi.create({ tunnel_server_id: serverId, address, label: label || null, is_primary: primary }),
    onSuccess: () => {
      onChanged()
      push('IP added', 'ok', 'ts://')
      onClose()
    },
    onError: (error: Error) => push(error.message, 'err', 'ts://'),
  })
  return (
    <Dialog
      title="Add public IP"
      scheme="POST /tunnel-server-ips"
      onClose={onClose}
      width={520}
      footer={
        <>
          <span className="left">The first IP becomes primary automatically.</span>
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!address || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? 'adding...' : 'Add IP'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Address" hint="IPv4 address that routes to this server.">
          <Input mono value={address} placeholder="185.213.44.21" onChange={(event) => setAddress(event.target.value)} autoFocus />
        </Field>
        <Field label="Label (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field>
        <Field label="Primary">
          <div className="row" style={{ gap: 8 }}>
            <Toggle on={primary} onChange={setPrimary} />
            <span style={{ fontSize: 12, color: 'var(--fg-2)' }}>{primary ? 'primary endpoint' : 'secondary IP'}</span>
          </div>
        </Field>
      </div>
    </Dialog>
  )
}
