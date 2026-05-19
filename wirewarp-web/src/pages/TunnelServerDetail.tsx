import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  agents as agentsApi,
  portForwards as pfApi,
  tunnelServers as tsApi,
} from '../lib/api'
import { Badge, Button, KV, Stat, StatusDot, Tabs, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import { WgPeerTable } from '../components/WgPeerTable'
import { CrowdSecCard } from '../components/CrowdSecCard'
import type { HealEvent } from '../lib/types'

type Tab = 'overview' | 'peers' | 'heal' | 'forwards'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export default function TunnelServerDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('overview')

  const summaryQ = useQuery({
    queryKey: ['tunnel-server-summary', id],
    queryFn: () => tsApi.summary(id!),
    enabled: !!id,
  })
  const peersQ = useQuery({
    queryKey: ['wg-peers', 'tunnel-server', id],
    queryFn: () => tsApi.wgPeers(id!),
    enabled: !!id,
  })
  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list })
  const forwardsQ = useQuery({
    queryKey: ['port-forwards', 'by-server', id],
    queryFn: () => pfApi.list({ tunnel_server_id: id }),
    enabled: !!id,
  })
  const s = summaryQ.data
  const a = s ? (agentsQ.data ?? []).find((x) => x.id === s.agent_id) : undefined

  const healQ = useQuery({
    queryKey: ['heal-events', s?.agent_id],
    queryFn: () => agentsApi.healEvents(s!.agent_id, 50),
    enabled: !!s?.agent_id,
  })

  if (summaryQ.isLoading) return <div className="page"><p>Loading…</p></div>
  if (!s) return <div className="page"><h1 className="page-title">Tunnel server not found</h1></div>

  return (
    <div className="page">
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <Link to="/tunnel-servers" style={{ color: 'inherit', cursor: 'pointer' }}>tunnel-servers</Link>
            <span className="sep">/</span>
            <span className="here mono">{s.id.slice(0, 12)}</span>
          </div>
          <h1 className="page-title">
            {a?.name || s.agent_id.slice(0, 8)}
            <StatusDot status={a?.status || 'disconnected'} />
          </h1>
          <p className="page-sub mono">
            {s.primary_ip || '—'} · {s.wg_interface}:{s.wg_port} · {s.tunnel_network}
          </p>
        </div>
        <div className="page-actions">
          <Button size="sm" variant="ghost" onClick={() => navigate(`/agents/${s.agent_id}`)}>
            open agent <Ic.arrow />
          </Button>
        </div>
      </div>

      <div className="server-stat-grid">
        <Stat label="peers" value={String(s.peer_count)} />
        <Stat label="rx" value={formatBytes(s.total_rx_bytes)} />
        <Stat label="tx" value={formatBytes(s.total_tx_bytes)} />
        <Stat label="forwards" value={String(s.forward_count)} />
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'peers', label: 'Peers', count: s.peer_count },
          {
            value: 'heal',
            label: (
              <>
                Heal events
                {s.recent_heal_count > 0 && <Badge tone="warn">{s.recent_heal_count}</Badge>}
              </>
            ),
          },
          { value: 'forwards', label: 'Forwards', count: s.forward_count },
        ]}
      />

      {tab === 'overview' && (
        <>
          <div className="card">
            <div className="card-head"><div className="title">Server</div></div>
            <div className="card-body" style={{ padding: 0 }}>
              <KV
                pairs={[
                  ['server id', s.id, true],
                  ['agent', a?.name || s.agent_id.slice(0, 8)],
                  ['public iface', s.public_iface, true],
                  ['primary ip', s.primary_ip || '—', true],
                  ['wg interface', `${s.wg_interface}:${s.wg_port}`, true],
                  ['network', s.tunnel_network, true],
                  ['wg pubkey', s.wg_public_key || '—', true],
                  ['created', new Date(s.created_at).toLocaleString(), true],
                ]}
              />
            </div>
          </div>
          <div style={{ marginTop: 14 }}>
            <CrowdSecCard serverId={s.id} />
          </div>
        </>
      )}

      {tab === 'peers' && <WgPeerTable peers={peersQ.data ?? []} />}

      {tab === 'heal' && <HealEventList events={healQ.data ?? []} loading={healQ.isLoading} />}

      {tab === 'forwards' && (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 60 }}>Proto</th>
                <th>Public</th>
                <th>Destination</th>
                <th>Description</th>
                <th style={{ width: 80 }}>State</th>
              </tr>
            </thead>
            <tbody>
              {(forwardsQ.data ?? []).length === 0 && (
                <tr>
                  <td colSpan={5}>
                    <div className="tbl-empty">
                      <h3>No forwards</h3>
                      <p>No port forwards routed through this server.</p>
                    </div>
                  </td>
                </tr>
              )}
              {(forwardsQ.data ?? []).map((p) => (
                <tr key={p.id} style={{ opacity: p.active ? 1 : 0.55 }}>
                  <td><Badge tone={p.protocol === 'tcp' ? 'info' : 'peer'}>{p.protocol}</Badge></td>
                  <td className="mono">
                    :{p.public_port_end ? `${p.public_port}-${p.public_port_end}` : p.public_port}
                    {p.sensitive_service && (
                      <span
                        title={p.sensitive_service.message}
                        style={{
                          marginLeft: 6,
                          fontSize: 10,
                          padding: '0 4px',
                          color: p.sensitive_service.severity === 'high' ? 'var(--err)' : 'var(--warn)',
                          background: p.sensitive_service.severity === 'high' ? 'var(--err-bg)' : 'var(--warn-bg)',
                          borderRadius: 2,
                        }}
                      >
                        {p.sensitive_service.severity === 'high' ? '⚠' : '!'} {p.sensitive_service.label}
                      </span>
                    )}
                  </td>
                  <td className="mono">
                    {p.destination_ip}:{p.destination_port_end ? `${p.destination_port}-${p.destination_port_end}` : p.destination_port}
                  </td>
                  <td style={{ color: 'var(--fg-2)' }}>{p.description || '—'}</td>
                  <td>
                    <Badge tone={p.active ? 'ok' : 'neutral'}>{p.active ? 'active' : 'off'}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function HealEventList({ events, loading }: { events: HealEvent[]; loading: boolean }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th style={{ width: 130 }}>When</th>
            <th style={{ width: 80 }}>Mode</th>
            <th style={{ width: 110 }}>Interface</th>
            <th>Healed items</th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 && (
            <tr>
              <td colSpan={4}>
                <div className="tbl-empty">
                  <h3>{loading ? 'loading…' : 'No drift recorded'}</h3>
                  <p>Routing state has been stable. The agent only emits an event when it actually re-installs missing rules.</p>
                </div>
              </td>
            </tr>
          )}
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(e.occurred_at)}</td>
              <td><Badge tone={e.mode === 'server' ? 'info' : 'neutral'}>{e.mode}</Badge></td>
              <td className="mono">{e.interface || '—'}</td>
              <td className="mono" style={{ color: 'var(--fg-1)' }}>{e.healed.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
