import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { security as secApi } from '../lib/api'
import { Badge, Button, Stat, Tabs, relTime } from '../components/ui'
import { UPlotChart } from '../components/UPlotChart'

type Range = '24h' | '7d' | '30d'

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

export default function SecurityOverview() {
  const [range, setRange] = useState<Range>('24h')

  const q = useQuery({
    queryKey: ['security-overview', range],
    queryFn: () => secApi.overview(range),
    refetchInterval: 30_000,
  })

  const data = q.data
  const kpis = data?.kpis

  // Build uPlot data from time series
  const accessSeries = data?.access_series ?? []
  const blockSeries = data?.block_series ?? []
  const timestamps = accessSeries.map((p) => Math.floor(new Date(p.t).getTime() / 1000))
  const accessValues = accessSeries.map((p) => p.value)
  const blockValues = blockSeries.map((p) => p.value)

  const hasChart = timestamps.length > 1

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>security</span>
          </div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-sub">Aggregated threat intel, traffic, and edge status.</p>
        </div>
        <div className="page-actions">
          <Tabs<Range>
            value={range}
            onChange={setRange}
            tabs={[
              { value: '24h', label: '24h' },
              { value: '7d', label: '7d' },
              { value: '30d', label: '30d' },
            ]}
          />
        </div>
      </div>

      {q.isLoading && <div style={{ padding: 24, color: 'var(--fg-3)' }}>Loading…</div>}
      {q.isError && <div className="card"><div className="card-body" role="alert">Could not load Security overview: {q.error.message}{data && <p>The rows below are the last loaded snapshot.</p>}<Button size="sm" onClick={() => q.refetch()}>Retry</Button></div></div>}
      {data && <>
      <div className="server-stat-grid">
        <Stat label="HTTP routes" value={data.http_routes_count} />
        <Stat label="Enabled route definitions" value={data.active_http_routes_count} />
        <Stat label="Edge nodes" value={data.servers.length} />
      </div>

      {kpis && (
        <div className="server-stat-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))' }}>
          <Stat label="Access" value={fmt(kpis.access)} />
          <Stat label="Visitors" value={fmt(kpis.visitors)} />
          <Stat label="Blocked" value={fmt(kpis.blocked)} />
          <Stat label="Attack IPs" value={fmt(kpis.attack_ips)} />
          <Stat label="4xx" value={fmt(kpis.err_4xx)} />
          <Stat label="5xx" value={fmt(kpis.err_5xx)} />
        </div>
      )}

      {hasChart && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="card-head">
            <div className="title">Access vs Blocked</div>
          </div>
          <div style={{ padding: '12px 14px 14px' }}>
            <UPlotChart
              timestamps={timestamps}
              series={[
                {
                  values: accessValues,
                  opts: { label: 'Access', stroke: 'var(--accent)', fill: 'oklch(from var(--accent) l c h / 0.12)', width: 1.5 },
                },
                {
                  values: blockValues,
                  opts: { label: 'Blocked', stroke: 'var(--err)', fill: 'oklch(from var(--err) l c h / 0.12)', width: 1.5 },
                },
              ]}
              height={160}
            />
          </div>
        </div>
      )}

      <div className="gridcols-2" style={{ gap: 12, marginTop: 14 }}>
        <div className="card">
          <div className="card-head"><div className="title">Top attackers</div></div>
          <div style={{ padding: '4px 0 8px' }}>
            {(data?.top_attackers ?? []).length === 0 && (
              <div style={{ padding: '10px 14px', color: 'var(--fg-3)', fontSize: 12 }}>
                No attack IPs detected.
              </div>
            )}
            {(data?.top_attackers ?? []).slice(0, 8).map((e, i) => (
              <div key={i} className="row" style={{ justifyContent: 'space-between', padding: '4px 14px', fontSize: 12 }}>
                <span className="mono" style={{ color: 'var(--fg-1)' }}>{e.ip ?? '—'}</span>
                <span className="mono" style={{ color: 'var(--err)' }}>{e.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><div className="title">Top scenarios</div></div>
          <div style={{ padding: '4px 0 8px' }}>
            {(data?.top_scenarios ?? []).length === 0 && (
              <div style={{ padding: '10px 14px', color: 'var(--fg-3)', fontSize: 12 }}>
                No scenarios triggered.
              </div>
            )}
            {(data?.top_scenarios ?? []).slice(0, 8).map((e, i) => (
              <div key={i} className="row" style={{ justifyContent: 'space-between', padding: '4px 14px', fontSize: 12 }}>
                <span className="mono" style={{ color: 'var(--fg-1)' }}>{e.name ?? '—'}</span>
                <span className="mono" style={{ color: 'var(--warn)' }}>{e.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head"><div className="title">Edge node status</div></div>
        <div className="card-body">Gateway edges serve local routes and inspect relayed public HTTP. VPS edges inspect public HTTP before tunnel transit. VPS relays pass TLS to gateways; they do not own WAF or certificates for relayed routes. Component columns show the last reported state.</div>
        <div className="tbl-wrap" style={{ marginTop: 0 }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Node</th>
                <th>Placement</th>
                <th>Edge capability</th>
                <th>Owned / relayed routes</th>
                <th>CrowdSec</th>
                <th>Traefik</th>
              </tr>
            </thead>
            <tbody>
              {(data?.servers ?? []).length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="tbl-empty">
                      <h3>No edge nodes</h3>
                      <p>No server or gateway nodes registered.</p>
                    </div>
                  </td>
                </tr>
              )}
              {(data?.servers ?? []).map((s) => (
                <tr key={s.agent_id}>
                  <td data-label="Node" style={{ whiteSpace: 'normal' }}>
                    <div><Link to={`/nodes/${s.agent_id}`} style={{ color: 'inherit' }}>{s.name || s.agent_id.slice(0, 12)}</Link>
                    <div className="scheme">{s.role}</div></div>
                  </td>
                  <td data-label="Placement" style={{ whiteSpace: 'normal' }}><div><Badge tone={s.placement === 'gateway_edge' ? 'peer' : 'info'}>{s.placement === 'gateway_edge' ? 'Gateway edge' : s.placement === 'vps_relay' ? 'VPS relay only' : 'VPS edge'}</Badge>{s.runtime_mode === 'relay_only' && <p className="scheme">TLS passthrough. WAF and certificates on the gateway.</p>}</div></td>
                  <td data-label="Edge capability" style={{ whiteSpace: 'normal' }}><div><Badge tone={s.edge_mode === 'security_edge' && s.edge_state === 'enabled' ? 'ok' : 'neutral'}>{s.edge_mode === 'security_edge' ? s.edge_state : 'TCP/UDP only'}</Badge><div className="scheme">{s.edge_install_phase}</div></div></td>
                  <td data-label="Owned / relayed routes" style={{ whiteSpace: 'normal' }}><div><span className="mono">{s.routes_count} owned · {s.relay_routes_count} relayed</span><div className="scheme">{s.active_routes_count} enabled definitions</div></div></td>
                  <td data-label="CrowdSec" style={{ whiteSpace: 'normal' }}><div>
                    {s.runtime_mode === 'relay_only' && <div className="scheme">Not used by relay</div>}
                    <ComponentReport installed={s.crowdsec_installed} running={s.crowdsec_running} phase={s.crowdsec_phase} error={s.crowdsec_error} updatedAt={s.crowdsec_updated_at} />
                    </div>
                  </td>
                  <td data-label="Traefik" style={{ whiteSpace: 'normal' }}>
                    <ComponentReport installed={s.traefik_installed} running={s.traefik_running} phase={s.traefik_phase} error={s.traefik_error} updatedAt={s.traefik_updated_at} relay={s.runtime_mode === 'relay_only'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      </>}
    </div>
  )
}

function ComponentReport({ installed, running, phase, error, updatedAt, relay }: { installed: boolean | null; running: boolean; phase: string | null; error: string | null; updatedAt: string | null; relay?: boolean }) {
  const status = installed == null ? 'No report' : running ? relay ? 'Relay running' : 'Running' : installed ? 'Installed, stopped' : 'Not installed'
  return <div><Badge tone={installed != null && running && phase === 'healthy' ? 'ok' : error || phase === 'degraded' ? 'warn' : 'neutral'}>{status}</Badge>{phase && <div className="scheme">{phase}</div>}{updatedAt && <div className="scheme">reported {relTime(updatedAt)}</div>}{error && <div role="alert" style={{ color: 'var(--err)', fontSize: 12 }}>{error}</div>}</div>
}
