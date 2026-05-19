import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { tunnelServers as tsApi } from '../lib/api'
import { useRole } from '../hooks/useRole'
import { useToast } from './Toasts'
import { Badge, Button, Stat } from './ui'

/** CrowdSec status card on the tunnel-server detail overview tab.
 *  Polled status comes from the server agent's 5-minute poller (see
 *  wirewarp-agent/internal/handlers/crowdsec.go). When cscli is missing
 *  on the host, `running: false` is the sentinel — render a muted card
 *  rather than nothing, so the operator can see the slot exists. */
export function CrowdSecCard({ serverId }: { serverId: string }) {
  const qc = useQueryClient()
  const push = useToast()
  const { isAdmin } = useRole()
  const q = useQuery({
    queryKey: ['crowdsec', serverId],
    queryFn: () => tsApi.crowdsec(serverId),
  })
  const data = q.data

  const install = useMutation({
    mutationFn: () => tsApi.installCrowdsec(serverId),
    onSuccess: () => {
      push('crowdsec install dispatched — install runs in the background and the card updates within 5 min', 'ok', 'cs://')
      qc.invalidateQueries({ queryKey: ['crowdsec', serverId] })
      qc.invalidateQueries({ queryKey: ['audit'] })
    },
    onError: (e: Error) => push(e.message, 'err', 'cs://'),
  })
  if (q.isLoading) {
    return (
      <div className="card">
        <div className="card-head"><div className="title">CrowdSec</div></div>
        <div style={{ padding: 14, color: 'var(--fg-3)', fontSize: 12 }}>loading…</div>
      </div>
    )
  }
  if (!data || !data.running) {
    return (
      <div className="card">
        <div className="card-head">
          <div className="title">CrowdSec</div>
          <Badge tone="neutral">not detected</Badge>
        </div>
        <div style={{ padding: 14, color: 'var(--fg-3)', fontSize: 12, lineHeight: 1.6 }}>
          CrowdSec is not running on this tunnel server. Recommended for SSH
          bruteforce, HTTP CVE, and mail abuse mitigation. WireWarp can install
          it on Debian-family hosts and auto-apply a whitelist covering every
          known IP / subnet in your environment (other agents, mesh + VPN
          subnets, gateway LAN subnets, discovered LAN clients).
          {data?.error && (
            <div style={{ marginTop: 8, color: 'var(--warn)' }}>
              last error: <span className="mono">{data.error}</span>
            </div>
          )}
          {isAdmin && (
            <div style={{ marginTop: 12 }}>
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  if (
                    confirm(
                      'Install CrowdSec on this tunnel server?\n\n' +
                        'Runs apt install + cscli capi register + collections install\n' +
                        'on the remote host as root (~1-2 min). Idempotent — re-run safely.',
                    )
                  ) {
                    install.mutate()
                  }
                }}
                disabled={install.isPending}
              >
                {install.isPending ? 'dispatching…' : 'Install CrowdSec'}
              </Button>
              <span style={{ marginLeft: 10, color: 'var(--fg-3)' }}>
                admin only · runs apt + cscli on the remote
              </span>
            </div>
          )}
        </div>
      </div>
    )
  }
  return (
    <div className="card">
      <div className="card-head">
        <div className="title">CrowdSec</div>
        <div className="row" style={{ gap: 8 }}>
          <Badge tone="ok">running</Badge>
          {data.version && <Badge tone="neutral">v{data.version}</Badge>}
        </div>
      </div>
      <div style={{ padding: '14px 14px 0' }}>
        <Stat label="active decisions" value={String(data.total_decisions)} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, padding: 14 }}>
        <div>
          <div className="field-label" style={{ marginBottom: 6 }}>Top scenarios</div>
          {data.top_scenarios.length === 0 && (
            <div style={{ color: 'var(--fg-3)', fontSize: 12 }}>none triggered yet</div>
          )}
          {data.top_scenarios.map((s) => (
            <div key={s.name} className="row" style={{ justifyContent: 'space-between', fontSize: 12, padding: '2px 0' }}>
              <span className="mono" style={{ color: 'var(--fg-1)' }}>{s.name}</span>
              <span className="mono" style={{ color: 'var(--fg-2)' }}>{s.count}</span>
            </div>
          ))}
        </div>
        <div>
          <div className="field-label" style={{ marginBottom: 6 }}>Top blocked IPs</div>
          {data.top_ips.length === 0 && (
            <div style={{ color: 'var(--fg-3)', fontSize: 12 }}>nothing on the ban list</div>
          )}
          {data.top_ips.map((ip) => (
            <div key={ip.ip} className="row" style={{ justifyContent: 'space-between', fontSize: 12, padding: '2px 0' }}>
              <span className="mono" style={{ color: 'var(--fg-1)' }}>{ip.ip}</span>
              <span className="mono" style={{ color: 'var(--fg-2)' }}>{ip.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
