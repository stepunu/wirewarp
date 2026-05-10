import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  tunnelClients as tunnelClientsApi,
  vpnEndpoints as vpnEndpointsApi,
  vpnProfiles as vpnProfilesApi,
} from '../lib/api'
import { Button, Field, Input, Toggle, relTime } from '../components/ui'
import { VpnPermissionsSheet } from '../components/VpnPermissionsSheet'
import type {
  TunnelClient,
  VpnEndpoint,
  VpnProfile,
} from '../lib/types'

export default function VpnEndpoints() {
  const qc = useQueryClient()
  const endpointsQ = useQuery({
    queryKey: ['vpn-endpoints'],
    queryFn: vpnEndpointsApi.list,
  })
  const profilesQ = useQuery({
    queryKey: ['vpn-profiles'],
    queryFn: () => vpnProfilesApi.list(),
  })
  const clientsQ = useQuery({
    queryKey: ['tunnel-clients'],
    queryFn: tunnelClientsApi.list,
  })

  const [permissionsFor, setPermissionsFor] = useState<VpnEndpoint | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)

  const delM = useMutation({
    mutationFn: vpnEndpointsApi.del,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vpn-endpoints'] }),
  })
  const patchM = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof vpnEndpointsApi.update>[1] }) =>
      vpnEndpointsApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vpn-endpoints'] }),
  })

  const gateways = (clientsQ.data ?? []).filter((c) => c.is_gateway)
  const peerCounts = countPeers(profilesQ.data ?? [])

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>VPN endpoints</h1>
          <p className="sub">
            Road-warrior WireGuard servers hosted on each gateway. Replaces wg-easy.
          </p>
        </div>
      </header>

      <CreateEndpointCard
        gateways={gateways}
        existingEndpointGatewayIds={new Set((endpointsQ.data ?? []).map((e) => e.tunnel_client_id))}
        onCreated={() => qc.invalidateQueries({ queryKey: ['vpn-endpoints'] })}
      />

      <div className="tbl-wrap" style={{ marginTop: 16 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Gateway</th>
              <th>Interface</th>
              <th>Listen port</th>
              <th>VPN /24</th>
              <th>Public endpoint</th>
              <th>Peers</th>
              <th>Enabled</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(endpointsQ.data ?? []).map((ep) =>
              editingId === ep.id ? (
                <EditEndpointRow
                  key={ep.id}
                  endpoint={ep}
                  gatewayName={
                    gateways.find((g) => g.id === ep.tunnel_client_id)?.lan_ip ??
                    ep.tunnel_client_id.slice(0, 8)
                  }
                  onCancel={() => setEditingId(null)}
                  onSaved={() => {
                    setEditingId(null)
                    qc.invalidateQueries({ queryKey: ['vpn-endpoints'] })
                  }}
                />
              ) : (
                <EndpointRow
                  key={ep.id}
                  endpoint={ep}
                  gatewayName={
                    gateways.find((g) => g.id === ep.tunnel_client_id)?.lan_ip ??
                    ep.tunnel_client_id.slice(0, 8)
                  }
                  peerCount={peerCounts[ep.id] ?? 0}
                  onPeers={() => setPermissionsFor(ep)}
                  onEdit={() => setEditingId(ep.id)}
                  onToggle={() =>
                    patchM.mutate({ id: ep.id, data: { enabled: !ep.enabled } })
                  }
                  onDelete={() => {
                    if (
                      confirm(
                        `Delete VPN endpoint on ${ep.public_endpoint}? Existing peers will lose connectivity.`,
                      )
                    ) {
                      delM.mutate(ep.id)
                    }
                  }}
                />
              ),
            )}
            {endpointsQ.data?.length === 0 && (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', color: 'var(--fg-3)', padding: 24 }}>
                  No VPN endpoints yet — create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {permissionsFor && (
        <VpnPermissionsSheet
          endpoint={permissionsFor}
          onClose={() => setPermissionsFor(null)}
        />
      )}
    </div>
  )
}

function EndpointRow({
  endpoint,
  gatewayName,
  peerCount,
  onPeers,
  onEdit,
  onToggle,
  onDelete,
}: {
  endpoint: VpnEndpoint
  gatewayName: string
  peerCount: number
  onPeers: () => void
  onEdit: () => void
  onToggle: () => void
  onDelete: () => void
}) {
  return (
    <tr>
      <td data-label="gateway"><strong>{gatewayName}</strong></td>
      <td data-label="interface"><code>{endpoint.wg_interface}</code></td>
      <td data-label="port"><code>{endpoint.listen_port}</code></td>
      <td data-label="network"><code>{endpoint.vpn_network}</code></td>
      <td data-label="public"><code>{endpoint.public_endpoint}</code></td>
      <td data-label="peers">
        <Button size="sm" variant="ghost" onClick={onPeers} title="Manage permissions">
          {peerCount}
        </Button>
      </td>
      <td data-label="enabled">
        <Toggle on={endpoint.enabled} onChange={onToggle} />
      </td>
      <td data-label="created">{relTime(endpoint.created_at)}</td>
      <td data-label="">
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          <Button size="sm" variant="ghost" onClick={onPeers}>
            Permissions
          </Button>
          <Button size="sm" variant="ghost" onClick={onEdit}>
            Edit
          </Button>
          <Button size="sm" variant="danger" onClick={onDelete}>
            Delete
          </Button>
        </div>
      </td>
    </tr>
  )
}

function countPeers(profiles: VpnProfile[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const p of profiles) {
    out[p.vpn_endpoint_id] = (out[p.vpn_endpoint_id] ?? 0) + 1
  }
  return out
}

function CreateEndpointCard({
  gateways,
  existingEndpointGatewayIds,
  onCreated,
}: {
  gateways: TunnelClient[]
  existingEndpointGatewayIds: Set<string>
  onCreated: () => void
}) {
  const [open, setOpen] = useState(false)
  const [tunnelClientId, setTunnelClientId] = useState('')
  const [publicEndpoint, setPublicEndpoint] = useState('')
  const [listenPort, setListenPort] = useState(51821)
  const [wgInterface, setWgInterface] = useState('wg-vpn0')
  const [dnsServers, setDnsServers] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const eligible = gateways.filter(
    (g) => !existingEndpointGatewayIds.has(g.id),
  )

  async function go(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await vpnEndpointsApi.create({
        tunnel_client_id: tunnelClientId,
        public_endpoint: publicEndpoint,
        listen_port: listenPort,
        wg_interface: wgInterface,
        dns_servers: dnsServers
          ? dnsServers.split(',').map((s) => s.trim()).filter(Boolean)
          : null,
      })
      onCreated()
      setOpen(false)
      setTunnelClientId('')
      setPublicEndpoint('')
      setListenPort(51821)
      setWgInterface('wg-vpn0')
      setDnsServers('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <Button onClick={() => setOpen(true)} variant="primary" disabled={eligible.length === 0}>
        + Create VPN endpoint
        {eligible.length === 0 && (
          <span style={{ marginLeft: 8, color: 'var(--fg-3)', fontSize: 11 }}>
            (no gateway without one)
          </span>
        )}
      </Button>
    )
  }

  return (
    <form className="card" style={{ padding: 16 }} onSubmit={go}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Field label="Gateway" hint="Only `is_gateway` clients without an existing endpoint are listed.">
          <select
            value={tunnelClientId}
            onChange={(e) => setTunnelClientId(e.target.value)}
            required
            className="select"
          >
            <option value="">Select gateway…</option>
            {eligible.map((g) => (
              <option key={g.id} value={g.id}>
                {g.lan_ip ?? g.id.slice(0, 8)} — {g.vm_network ?? 'no LAN'}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Interface" hint="Linux interface name. wg-easy commonly uses wg0; pick something distinct so they coexist.">
          <Input mono value={wgInterface} onChange={(e) => setWgInterface(e.target.value)} />
        </Field>
        <Field
          label="Public endpoint"
          hint="DNS:port (or IP:port) the .conf points clients at. Must be reachable from the public internet."
        >
          <Input
            mono
            value={publicEndpoint}
            onChange={(e) => setPublicEndpoint(e.target.value)}
            placeholder="vpn.example.com:51821"
            required
          />
        </Field>
        <Field label="Listen port">
          <Input
            type="number"
            mono
            value={listenPort}
            onChange={(e) => setListenPort(parseInt(e.target.value, 10) || 0)}
            min={1}
            max={65535}
          />
        </Field>
        <Field
          label="DNS servers + match domains (optional, comma-separated)"
          hint={
            <>
              First entries are DNS server IPs (e.g. <code>192.168.1.5</code>). Trailing
              entries that look like hostnames are treated as <strong>match domains</strong> —
              iOS / macOS clients route queries for any name ending in these suffixes through
              the WG-side DNS, fixing the split-DNS race that otherwise sends internal-domain
              lookups to cellular DNS. List every internal suffix you use (e.g.{' '}
              <code>example.com, home.example.com, infra.example.com</code>).
            </>
          }
        >
          <Input
            mono
            value={dnsServers}
            onChange={(e) => setDnsServers(e.target.value)}
            placeholder="192.168.1.5, home.example.com, infra.example.com"
          />
        </Field>
      </div>
      {error && <div style={{ marginTop: 12, color: 'var(--err)' }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}>
        <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={busy || !tunnelClientId}>
          {busy ? 'creating…' : 'Create'}
        </Button>
      </div>
    </form>
  )
}


function EditEndpointRow({
  endpoint,
  gatewayName,
  onCancel,
  onSaved,
}: {
  endpoint: VpnEndpoint
  gatewayName: string
  onCancel: () => void
  onSaved: () => void
}) {
  const [publicEndpoint, setPublicEndpoint] = useState(endpoint.public_endpoint)
  const [listenPort, setListenPort] = useState(endpoint.listen_port)
  const [dnsServers, setDnsServers] = useState(
    (endpoint.dns_servers ?? []).join(', '),
  )
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function save() {
    setBusy(true)
    setError(null)
    try {
      await vpnEndpointsApi.update(endpoint.id, {
        public_endpoint: publicEndpoint.trim(),
        listen_port: listenPort,
        dns_servers: dnsServers
          ? dnsServers.split(',').map((s) => s.trim()).filter(Boolean)
          : null,
      })
      onSaved()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <tr>
      <td data-label="gateway"><strong>{gatewayName}</strong></td>
      <td data-label="interface"><code>{endpoint.wg_interface}</code></td>
      <td data-label="port">
        <Input
          mono
          type="number"
          min={1}
          max={65535}
          value={listenPort}
          onChange={(e) => setListenPort(parseInt(e.target.value, 10) || 0)}
          style={{ width: 90 }}
        />
      </td>
      <td data-label="network"><code>{endpoint.vpn_network}</code></td>
      <td data-label="public">
        <Input
          mono
          value={publicEndpoint}
          onChange={(e) => setPublicEndpoint(e.target.value)}
          placeholder="ddns.example.com:51821"
          style={{ width: '100%' }}
        />
      </td>
      <td data-label="dns" colSpan={3}>
        <Input
          mono
          value={dnsServers}
          onChange={(e) => setDnsServers(e.target.value)}
          placeholder="192.168.1.5, home.example.com, infra.example.com"
          style={{ width: '100%' }}
          title="DNS servers + match domains (comma-separated)"
        />
        {error && (
          <div style={{ marginTop: 4, color: 'var(--err)', fontSize: 11 }}>
            {error}
          </div>
        )}
      </td>
      <td data-label="">
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          <Button size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            size="sm"
            variant="primary"
            onClick={save}
            disabled={busy || !publicEndpoint.trim()}
          >
            {busy ? 'saving…' : 'Save'}
          </Button>
        </div>
      </td>
    </tr>
  )
}

