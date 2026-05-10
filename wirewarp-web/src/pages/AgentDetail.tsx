import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  agents as agentsApi,
  audit as auditApi,
  tunnelClients as tcApi,
  tunnelServers as tsApi,
  tunnelServerIPs as ipApi,
} from '../lib/api'
import { Badge, Button, Dialog, KV, StatusDot, Tabs, relTime } from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'

type Tab = 'overview' | 'config' | 'audit'

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const push = useToast()
  const [tab, setTab] = useState<Tab>('overview')
  const [jwtModal, setJwtModal] = useState<string | null>(null)

  const agentQ = useQuery({
    queryKey: ['agent', id],
    queryFn: () => agentsApi.get(id!),
    
    enabled: !!id,
  })
  const tsList = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list }).data ?? []
  const tcList = useQuery({ queryKey: ['tunnel-clients'], queryFn: tcApi.list }).data ?? []

  const a = agentQ.data
  const ts = a ? tsList.find((s) => s.agent_id === a.id) : undefined
  const tc = a ? tcList.find((c) => c.agent_id === a.id) : undefined
  const isServer = a?.type === 'server'

  const ipsQ = useQuery({
    queryKey: ['tunnel-server-ips', ts?.id],
    queryFn: () => ipApi.list(ts!.id),
    enabled: !!ts?.id,
  })

  const auditQ = useQuery({
    queryKey: ['audit', id],
    queryFn: () => auditApi.list({ agent_id: id, limit: 100 }),
    enabled: tab === 'audit' && !!id,
  })

  const deleteAgent = useMutation({
    mutationFn: () => agentsApi.del(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      push('agent removed', 'ok', 'agent://')
      navigate('/agents')
    },
  })
  const issueJwt = useMutation({
    mutationFn: () => agentsApi.issueJwt(id!),
    onSuccess: (data) => setJwtModal(data.jwt),
  })
  const updateAgent = useMutation({
    mutationFn: () => agentsApi.update(id!),
    onSuccess: () => push('update queued', 'ok', 'agent://'),
    onError: (e) => push(e instanceof Error ? e.message : 'update failed', 'err', 'agent://'),
  })

  if (agentQ.isLoading) return <div className="page"><p>Loading…</p></div>
  if (!a) return <div className="page"><h1 className="page-title">Agent not found</h1></div>

  const ipCount = ipsQ.data?.length ?? ts?.ips.length ?? 0
  const pfCount = (ipsQ.data ?? []).reduce((s, ip) => s + (ip.port_forward_count || 0), 0)

  return (
    <div className="page">
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <Link to="/agents" style={{ color: 'inherit', cursor: 'pointer' }}>agents</Link>
            <span className="sep">/</span>
            <span className="here mono">{a.id.slice(0, 12)}</span>
          </div>
          <h1 className="page-title">
            {a.name}
            <Badge tone={a.type === 'server' ? 'info' : 'neutral'}>{a.type}</Badge>
            <StatusDot status={a.status} />
          </h1>
          <p className="page-sub mono">
            {a.hostname || '—'} · v{a.version || '—'} · last seen {relTime(a.last_seen)}
          </p>
        </div>
        <div className="page-actions">
          <Button
            size="sm"
            onClick={() => issueJwt.mutate()}
            disabled={issueJwt.isPending}
          >
            {issueJwt.isPending ? 'issuing…' : 'reissue jwt'}
          </Button>
          <Button
            size="sm"
            variant="primary"
            onClick={() => updateAgent.mutate()}
            disabled={updateAgent.isPending || a.status !== 'connected'}
            title={a.status !== 'connected' ? 'agent must be connected' : ''}
          >
            {updateAgent.isPending ? 'updating…' : 'update agent'}
          </Button>
          <Button
            size="sm"
            variant="danger"
            leading={<Ic.trash />}
            onClick={() => {
              if (confirm(`Delete agent ${a.name}?`)) deleteAgent.mutate()
            }}
          >
            remove
          </Button>
        </div>
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'config', label: 'Config' },
          { value: 'audit', label: 'Audit log' },
        ]}
      />

      {tab === 'overview' && (
        <div className="agent-detail-grid">
          <div className="card">
            <div className="card-head"><div className="title">Identity</div></div>
            <div className="card-body" style={{ padding: 0 }}>
              <KV
                pairs={[
                  ['agent id', a.id, true],
                  ['name', a.name],
                  ['type', a.type],
                  ['hostname', a.hostname || '—', true],
                  ['public ip', a.public_ip || '—', true],
                  ['version', a.version || '—', true],
                  ['created', new Date(a.created_at).toLocaleString(), true],
                ]}
              />
            </div>
          </div>
          <div className="card">
            <div className="card-head">
              <div className="title">{isServer ? 'Tunnel server' : 'Tunnel client'}</div>
              {isServer && ts && (
                <Link to={`/tunnel-servers#ts_${ts.id}`} style={{ textDecoration: 'none' }}>
                  <Button size="sm" variant="ghost">
                    manage IPs <Ic.arrow />
                  </Button>
                </Link>
              )}
            </div>
            <div className="card-body" style={{ padding: 0 }}>
              {isServer && ts && (
                <KV
                  pairs={[
                    ['wg interface', ts.wg_interface, true],
                    ['wg port', String(ts.wg_port), true],
                    ['public iface', ts.public_iface, true],
                    ['network', ts.tunnel_network, true],
                    ['pubkey', ts.wg_public_key || '—', true],
                    ['public ips', `${ipCount} configured`],
                    ['forwards', `${pfCount} rules`],
                  ]}
                />
              )}
              {!isServer && tc && (
                <KV
                  pairs={[
                    ['attachments', String(tc.attachments.length), true],
                    ['lan ip', tc.lan_ip || '—', true],
                    ['vm network', tc.vm_network || '—', true],
                    ['gateway', tc.is_gateway ? 'yes' : 'no'],
                    ['status', tc.status],
                  ]}
                />
              )}
              {!isServer && !tc && (
                <div style={{ padding: 14, color: 'var(--fg-3)', fontSize: 12 }}>
                  No tunnel client config yet.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {tab === 'config' && (
        <div className="card">
          <div className="card-head">
            <div className="title">Inferred WireGuard state</div>
          </div>
          <pre className="code" style={{ margin: 14, padding: 14 }}>
{isServer && ts
  ? `interface: ${ts.wg_interface}
  public key: ${ts.wg_public_key || '(not yet set)'}
  listening port: ${ts.wg_port}

network: ${ts.tunnel_network}
public ips: ${ipCount}
active forwards: ${pfCount}`
  : tc
  ? `attachments: ${tc.attachments.length}
${tc.attachments.map((a) => `  - ${a.wg_interface} ${a.tunnel_ip} (server ${a.tunnel_server_id.slice(0, 8)}, fwmark 0x${a.fwmark.toString(16)}, table ${a.route_table_id})`).join('\n') || '  (none yet)'}
lan ip: ${tc.lan_ip || '—'}
gateway: ${tc.is_gateway ? 'yes' : 'no'}
status: ${tc.status}`
  : 'No config yet.'}
          </pre>
        </div>
      )}

      {tab === 'audit' && (
        <div className="card">
          <div className="card-head">
            <div className="title">Commands sent to this agent</div>
            <span className="scheme">audit · last 100</span>
          </div>
          <div
            className="log"
            style={{ margin: 0, border: 'none', borderRadius: 0, maxHeight: 480 }}
          >
            {(auditQ.data ?? []).length === 0 && (
              <div style={{ padding: 16, color: 'var(--fg-3)', fontSize: 12 }}>
                {auditQ.isLoading ? 'loading…' : 'No commands yet.'}
              </div>
            )}
            {(auditQ.data ?? []).map((l) => (
              <div className="line" key={l.id}>
                <span className="ts mono">{relTime(l.executed_at).padStart(8, ' ')}</span>
                <span className={`lvl ${l.success === false ? 'err' : l.success === true ? 'ok' : 'info'}`}>
                  {l.success === false ? 'FAIL' : l.success === true ? 'OK' : 'INFO'}
                </span>
                <span className="msg mono">
                  {l.command_type}
                  {l.output ? `  ${l.output.slice(0, 200)}` : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {jwtModal && <JwtDialog jwt={jwtModal} onClose={() => setJwtModal(null)} />}
    </div>
  )
}

function JwtDialog({ jwt, onClose }: { jwt: string; onClose: () => void }) {
  const push = useToast()
  const sed = `sudo sed -i "s|^agent_jwt:.*|agent_jwt: ${jwt}|" /etc/wirewarp/agent.yaml\nsudo systemctl restart wirewarp-agent`
  return (
    <Dialog
      title="New agent JWT"
      scheme="POST /agents/{id}/issue-jwt"
      onClose={onClose}
      width={680}
      footer={
        <>
          <span className="left">JWT shown once.</span>
          <div className="right">
            <Button onClick={onClose}>Close</Button>
          </div>
        </>
      }
    >
      <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--fg-2)' }}>
        Apply on the agent machine. The agent reconnects without losing config or WG state.
      </div>
      <div className="field-label" style={{ marginBottom: 4 }}>JWT</div>
      <pre className="code" style={{ marginBottom: 8 }}>{jwt}</pre>
      <Button
        size="sm"
        variant="ghost"
        leading={<Ic.copy />}
        onClick={() => {
          navigator.clipboard.writeText(jwt)
          push('jwt copied', 'ok', 'clip://')
        }}
      >
        copy jwt
      </Button>
      <div className="field-label" style={{ marginTop: 14, marginBottom: 4 }}>Apply</div>
      <pre className="code">{sed}</pre>
      <Button
        size="sm"
        variant="ghost"
        leading={<Ic.copy />}
        onClick={() => {
          navigator.clipboard.writeText(sed)
          push('command copied', 'ok', 'clip://')
        }}
      >
        copy command
      </Button>
    </Dialog>
  )
}
