import { useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { security as secApi } from '../lib/api'
import { Badge, FilterBar, Sheet, KV, relTime } from '../components/ui'
import type { SecurityEvent } from '../lib/types'

const SOURCE_TONES: Record<string, 'err' | 'warn' | 'info' | 'neutral'> = {
  crowdsec: 'err',
  appsec: 'warn',
  traefik: 'info',
}

const ACTION_TONES: Record<string, 'err' | 'warn' | 'ok' | 'neutral'> = {
  ban: 'err',
  captcha: 'warn',
  log: 'neutral',
}

export default function SecurityEvents() {
  const [filter, setFilter] = useState('')
  const [source, setSource] = useState('all')
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)

  const q = useQuery({
    queryKey: ['security-events', source],
    queryFn: () => secApi.events({ limit: 200, source: source !== 'all' ? source : undefined }),
    refetchInterval: 15_000,
  })

  const events = q.data ?? []

  const filtered = events.filter((e) => {
    if (filter) {
      const f = filter.toLowerCase()
      return [e.kind, e.ip, e.value, e.source, e.action]
        .filter(Boolean)
        .some((x) => x!.toLowerCase().includes(f))
    }
    return true
  })

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>security</span>
            <span className="sep">/</span>
            <span>events</span>
          </div>
          <h1 className="page-title">Security Events</h1>
          <p className="page-sub">CrowdSec decisions, AppSec alerts, and Traefik access log anomalies.</p>
        </div>
      </div>

      <FilterBar
        filterRef={filterRef}
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'source',
            value: source,
            onChange: setSource,
            options: [
              ['all', 'all'],
              ['crowdsec', 'crowdsec'],
              ['appsec', 'appsec'],
              ['traefik', 'traefik'],
            ],
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{events.length}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 130 }}>When</th>
              <th style={{ width: 80 }}>Source</th>
              <th>Kind</th>
              <th>IP</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className="tbl-empty">
                    <h3>{q.isLoading ? 'Loading…' : 'No events'}</h3>
                    <p>No security events match the current filter.</p>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((e) => (
              <tr
                key={e.id}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelected(e)}
              >
                <td className="mono" style={{ color: 'var(--fg-2)' }}>{relTime(e.occurred_at)}</td>
                <td>
                  <Badge tone={SOURCE_TONES[e.source] ?? 'neutral'}>{e.source}</Badge>
                </td>
                <td className="mono">{e.kind}</td>
                <td className="mono" style={{ color: 'var(--fg-1)' }}>{e.ip ?? '—'}</td>
                <td>
                  {e.action ? (
                    <Badge tone={ACTION_TONES[e.action] ?? 'neutral'}>{e.action}</Badge>
                  ) : (
                    <span style={{ color: 'var(--fg-3)' }}>—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <Sheet onClose={() => setSelected(null)} width={420}>
          <div style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <div className="mono" style={{ fontSize: 14, marginBottom: 4 }}>{selected.kind}</div>
                <div style={{ color: 'var(--fg-3)', fontSize: 12 }}>{relTime(selected.occurred_at)}</div>
              </div>
              <Badge tone={SOURCE_TONES[selected.source] ?? 'neutral'}>{selected.source}</Badge>
            </div>
            <KV
              pairs={[
                ['IP', selected.ip ?? '—', !!selected.ip],
                ['Value', selected.value ?? '—'],
                ['Action', selected.action ?? '—'],
                ['When', new Date(selected.occurred_at).toLocaleString()],
                ['Agent', selected.agent_id.slice(0, 12), true],
              ]}
            />
            {selected.raw && (
              <div style={{ marginTop: 14 }}>
                <div className="field-label" style={{ marginBottom: 6 }}>Raw payload</div>
                <pre
                  className="code"
                  style={{ fontSize: 11, maxHeight: 220, overflow: 'auto' }}
                >
                  {JSON.stringify(selected.raw, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </Sheet>
      )}
    </div>
  )
}
