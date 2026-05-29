import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { security as secApi, tunnelServers as tsApi } from '../lib/api'
import { Badge, FilterBar } from '../components/ui'

export default function SecurityBans() {
  const [filter, setFilter] = useState('')
  const [serverId, setServerId] = useState('all')

  const serversQ = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list })

  const bansQ = useQuery({
    queryKey: ['security-bans', serverId],
    queryFn: () => secApi.bans(serverId !== 'all' ? { server_id: serverId } : {}),
    refetchInterval: 30_000,
  })

  const bans = bansQ.data ?? []

  const filtered = bans.filter((b) => {
    if (!filter) return true
    return b.ip.toLowerCase().includes(filter.toLowerCase())
  })

  const serverOptions: [string, string][] = [
    ['all', 'all servers'],
    ...(serversQ.data ?? []).map((s): [string, string] => [s.id, s.id.slice(0, 12)]),
  ]

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>security</span>
            <span className="sep">/</span>
            <span>bans</span>
          </div>
          <h1 className="page-title">Bans</h1>
          <p className="page-sub">
            Active CrowdSec decisions and known banned IPs. Read-only view.
            {/* TODO: manual ban/unban via cscli decisions add/delete (Phase 12.6) */}
          </p>
        </div>
      </div>

      <FilterBar
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'server',
            value: serverId,
            onChange: setServerId,
            options: serverOptions,
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length} ban{filtered.length !== 1 ? 's' : ''}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>IP</th>
              <th>Source</th>
              <th style={{ width: 80 }}>Count</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={3}>
                  <div className="tbl-empty">
                    <h3>{bansQ.isLoading ? 'Loading…' : 'No bans'}</h3>
                    <p>No IPs are currently banned on the selected server(s).</p>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((b, i) => (
              <tr key={i}>
                <td className="mono">{b.ip}</td>
                <td>
                  <Badge tone={b.source === 'crowdsec' ? 'err' : 'warn'}>{b.source}</Badge>
                </td>
                <td className="mono" style={{ color: 'var(--fg-2)' }}>{b.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
