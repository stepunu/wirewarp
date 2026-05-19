import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  agents as agentsApi,
  tunnelClients as tcApi,
  tunnelServers as tsApi,
} from '../lib/api'
import { Badge, Button, KV, Stat, StatusDot, Tabs } from '../components/ui'
import { Ic } from '../components/icons'
import { WgPeerTable } from '../components/WgPeerTable'
import { HealEventList } from './TunnelServerDetail'

type Tab = 'overview' | 'attachments' | 'heal'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function handshakeAge(unix: number | null): string {
  if (!unix) return 'never'
  const ageSec = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  if (ageSec < 60) return `${ageSec}s`
  if (ageSec < 3600) return `${Math.floor(ageSec / 60)}m`
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h`
  return `${Math.floor(ageSec / 86400)}d`
}

function handshakeTone(unix: number | null): 'ok' | 'warn' | 'err' {
  if (!unix) return 'err'
  const age = Date.now() / 1000 - unix
  if (age < 180) return 'ok'
  if (age < 900) return 'warn'
  return 'err'
}

export default function TunnelClientDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('overview')

  const summaryQ = useQuery({
    queryKey: ['tunnel-client-summary', id],
    queryFn: () => tcApi.summary(id!),
    enabled: !!id,
  })
  const peersQ = useQuery({
    queryKey: ['wg-peers', 'tunnel-client', id],
    queryFn: () => tcApi.wgPeers(id!),
    enabled: !!id,
  })
  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list })
  const serversQ = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list })

  const s = summaryQ.data
  const a = s ? (agentsQ.data ?? []).find((x) => x.id === s.agent_id) : undefined

  const healQ = useQuery({
    queryKey: ['heal-events', s?.agent_id],
    queryFn: () => agentsApi.healEvents(s!.agent_id, 50),
    enabled: !!s?.agent_id,
  })

  if (summaryQ.isLoading) return <div className="page"><p>Loading…</p></div>
  if (!s) return <div className="page"><h1 className="page-title">Tunnel client not found</h1></div>

  const serverNameFor = (serverId: string) => {
    const sv = (serversQ.data ?? []).find((x) => x.id === serverId)
    if (!sv) return serverId.slice(0, 8)
    const ag = (agentsQ.data ?? []).find((x) => x.id === sv.agent_id)
    return ag?.name || sv.id.slice(0, 8)
  }

  return (
    <div className="page">
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <Link to="/tunnel-clients" style={{ color: 'inherit', cursor: 'pointer' }}>tunnel-clients</Link>
            <span className="sep">/</span>
            <span className="here mono">{s.id.slice(0, 12)}</span>
          </div>
          <h1 className="page-title">
            {a?.name || s.agent_id.slice(0, 8)}
            <StatusDot status={s.status} />
            {s.is_gateway && <Badge tone="peer">gateway</Badge>}
          </h1>
          <p className="page-sub mono">
            {s.lan_ip || '—'} · {s.vm_network || '—'} · {s.attachments.length} attachment{s.attachments.length === 1 ? '' : 's'}
          </p>
        </div>
        <div className="page-actions">
          <Button size="sm" variant="ghost" onClick={() => navigate(`/agents/${s.agent_id}`)}>
            open agent <Ic.arrow />
          </Button>
        </div>
      </div>

      <div className="server-stat-grid">
        <Stat label="attachments" value={String(s.attachments.length)} />
        <Stat label="rx" value={formatBytes(s.total_rx_bytes)} />
        <Stat label="tx" value={formatBytes(s.total_tx_bytes)} />
        <Stat label="status" value={s.status} />
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'attachments', label: 'Attachments', count: s.attachments.length },
          {
            value: 'heal',
            label: (
              <>
                Heal events
                {s.recent_heal_count > 0 && <Badge tone="warn">{s.recent_heal_count}</Badge>}
              </>
            ),
          },
        ]}
      />

      {tab === 'overview' && (
        <div className="card">
          <div className="card-head"><div className="title">Client</div></div>
          <div className="card-body" style={{ padding: 0 }}>
            <KV
              pairs={[
                ['client id', s.id, true],
                ['agent', a?.name || s.agent_id.slice(0, 8)],
                ['lan ip', s.lan_ip || '—', true],
                ['vm network', s.vm_network || '—', true],
                ['is gateway', s.is_gateway ? 'yes' : 'no'],
                ['status', s.status],
                ['created', new Date(s.created_at).toLocaleString(), true],
              ]}
            />
          </div>
        </div>
      )}

      {tab === 'attachments' && (
        <>
          {s.attachments.length === 0 && (
            <div className="empty">
              <div className="glyph"><Ic.host s={16} /></div>
              <h3>No attachments</h3>
              <p>This client is not attached to any tunnel server yet.</p>
            </div>
          )}
          {s.attachments.map((att) => {
            const health = s.attachment_health.find((h) => h.attachment_id === att.id)
            const ifacePeers = (peersQ.data ?? []).filter((p) => p.interface === att.wg_interface)
            return (
              <div key={att.id} className="card" style={{ marginBottom: 14 }}>
                <div className="card-head">
                  <div className="title mono">{att.wg_interface}</div>
                  <div className="row" style={{ gap: 8 }}>
                    <Badge tone="peer">{serverNameFor(att.tunnel_server_id)}</Badge>
                    <Badge tone={handshakeTone(health?.last_handshake_unix ?? null)}>
                      handshake {handshakeAge(health?.last_handshake_unix ?? null)}
                    </Badge>
                    <span className="scheme">peers · {health?.peer_count ?? 0}</span>
                  </div>
                </div>
                <div className="card-body" style={{ padding: 0 }}>
                  <KV
                    pairs={[
                      ['tunnel ip', att.tunnel_ip, true],
                      ['fwmark', `0x${att.fwmark.toString(16)}`, true],
                      ['route table', String(att.route_table_id), true],
                      ['pubkey', att.wg_public_key || '—', true],
                    ]}
                  />
                </div>
                <WgPeerTable peers={ifacePeers} />
              </div>
            )
          })}
        </>
      )}

      {tab === 'heal' && <HealEventList events={healQ.data ?? []} loading={healQ.isLoading} />}
    </div>
  )
}
