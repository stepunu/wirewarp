import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  agents as agentsApi,
  portForwards as pfApi,
  tunnelServers as tsApi,
  tunnelClients as tcApi,
  audit as auditApi,
} from '../lib/api'
import { Badge, Button, StatusDot, relTime } from '../components/ui'
import { Ic } from '../components/icons'

export default function Dashboard() {
  const agents = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list }).data ?? []
  const pf = useQuery({ queryKey: ['port-forwards'], queryFn: () => pfApi.list() }).data ?? []
  const ts = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const tc = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []
  const audit = useQuery({
    queryKey: ['audit', 50],
    queryFn: () => auditApi.list({ limit: 50 }),
    
  }).data ?? []

  const connected = agents.filter((a) => a.status === 'connected').length
  const disconnected = agents.filter((a) => a.status === 'disconnected').length
  const pending = agents.filter((a) => a.status === 'pending').length
  const activePF = pf.filter((p) => p.active).length
  const totalPublicIPs = ts.reduce((s, t) => s + (t.ips?.length || 0), 0)
  const onlineClients = tc.filter((c) => c.status === 'online' || c.status === 'connected').length

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>overview</span>
          </div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub">Health of your tunnel mesh, in one glance.</p>
        </div>
        <div className="page-actions">
          <Link to="/port-forwards?new=1" style={{ textDecoration: 'none' }}>
            <Button variant="primary" leading={<Ic.plus />}>
              New forward
              <span className="kbd-inline">N</span>
            </Button>
          </Link>
        </div>
      </div>

      <div className="stat-row" style={{ marginBottom: 16 }}>
        <Stat label="Tunnel servers" value={ts.length} delta={`${totalPublicIPs} public IPs`} />
        <Stat label="Tunnel clients" value={tc.length} delta={`${onlineClients} online`} deltaTone="up" />
        <Stat
          label="Agents · live"
          value={
            <>
              {connected}/<span style={{ color: 'var(--fg-2)' }}>{agents.length}</span>
            </>
          }
          delta={
            <>
              <span style={{ color: 'var(--err)' }}>{disconnected} offline</span>
              {pending > 0 && (
                <>
                  {' · '}
                  <span style={{ color: 'var(--warn)' }}>{pending} pending</span>
                </>
              )}
            </>
          }
        />
        <Stat
          label="Port forwards"
          value={
            <>
              {activePF}/<span style={{ color: 'var(--fg-2)' }}>{pf.length}</span>
            </>
          }
          delta={`${pf.length - activePF} disabled`}
        />
      </div>

      <div className="dash-main-grid">
        <div className="card">
          <div className="card-head">
            <div className="title">Activity <span className="scheme">audit · last 50</span></div>
          </div>
          <div className="log" style={{ margin: 0, border: 'none', borderRadius: 0, maxHeight: 420 }}>
            {audit.length === 0 && (
              <div style={{ padding: 16, color: 'var(--fg-3)', fontSize: 12 }}>No commands logged yet.</div>
            )}
            {audit.map((l) => (
              <div className="line" key={l.id}>
                <span className="ts mono">{relTime(l.executed_at).padStart(8, ' ')}</span>
                <span className={`lvl ${l.success === false ? 'err' : l.success === true ? 'ok' : 'info'}`}>
                  {l.success === false ? 'FAIL' : l.success === true ? 'OK' : 'INFO'}
                </span>
                <span className="msg">
                  <span className="scheme">{l.agent_name ? `agent:${l.agent_name}` : 'system'}</span>
                  {'  '}
                  {l.command_type}
                  {l.output ? `  ${l.output.slice(0, 200)}` : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <div className="title">Recent agents</div>
            <Link to="/agents" style={{ textDecoration: 'none' }}>
              <Button variant="ghost" size="sm">view all <Ic.chevR /></Button>
            </Link>
          </div>
          <div className="tbl-wrap" style={{ border: 'none', borderRadius: 0 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.slice(0, 8).map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/agents/${a.id}`} className="tbl-link mono">
                        {a.name}
                      </Link>
                    </td>
                    <td>
                      <Badge tone={a.type === 'server' ? 'info' : 'neutral'}>{a.type}</Badge>
                    </td>
                    <td><StatusDot status={a.status} /></td>
                    <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(a.last_seen)}</td>
                  </tr>
                ))}
                {agents.length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ padding: 24, textAlign: 'center', color: 'var(--fg-3)' }}>
                      No agents yet. <Link to="/agents" className="tbl-link">Issue a token →</Link>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
  delta,
  deltaTone,
}: {
  label: string
  value: React.ReactNode
  delta?: React.ReactNode
  deltaTone?: 'up' | 'down'
}) {
  return (
    <div className="stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value tabnum">{value}</span>
      {delta && <span className={`stat-delta ${deltaTone || ''}`}>{delta}</span>}
    </div>
  )
}
