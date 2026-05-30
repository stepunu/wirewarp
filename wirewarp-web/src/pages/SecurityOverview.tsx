import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { security as secApi } from '../lib/api'
import { Badge, Stat, Tabs } from '../components/ui'
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

      {kpis && (
        <div className="server-stat-grid" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
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

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 14 }}>
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
        <div className="card-head"><div className="title">Server status</div></div>
        <div className="tbl-wrap" style={{ marginTop: 0 }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Server</th>
                <th>CrowdSec</th>
                <th>Traefik</th>
              </tr>
            </thead>
            <tbody>
              {(data?.servers ?? []).length === 0 && (
                <tr>
                  <td colSpan={3}>
                    <div className="tbl-empty">
                      <h3>No servers</h3>
                      <p>No tunnel servers registered.</p>
                    </div>
                  </td>
                </tr>
              )}
              {(data?.servers ?? []).map((s) => (
                <tr key={s.server_id}>
                  <td className="mono">
                    {s.agent_id ? (
                      <Link to={`/nodes/${s.agent_id}`} style={{ color: 'inherit' }}>
                        {s.name ?? s.server_id.slice(0, 12)}
                      </Link>
                    ) : (
                      s.name ?? s.server_id.slice(0, 12)
                    )}
                  </td>
                  <td>
                    <Badge tone={s.crowdsec_running ? 'ok' : 'neutral'}>
                      {s.crowdsec_running ? 'running' : 'off'}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={s.traefik_running ? 'ok' : 'neutral'}>
                      {s.traefik_running ? 'running' : 'off'}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
