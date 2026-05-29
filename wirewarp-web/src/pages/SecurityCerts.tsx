import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { security as secApi, tunnelServers as tsApi } from '../lib/api'
import { Badge, FilterBar } from '../components/ui'

const STATUS_TONES = {
  managed: 'ok' as const,
  pending: 'warn' as const,
  error: 'err' as const,
}

export default function SecurityCerts() {
  const [filter, setFilter] = useState('')
  const [serverId, setServerId] = useState('all')

  const serversQ = useQuery({ queryKey: ['tunnel-servers'], queryFn: tsApi.list })

  const certsQ = useQuery({
    queryKey: ['security-certs', serverId],
    queryFn: () => secApi.certs(serverId !== 'all' ? { server_id: serverId } : {}),
    refetchInterval: 60_000,
  })

  const certs = certsQ.data ?? []

  const filtered = certs.filter((c) => {
    if (!filter) return true
    return c.domain.toLowerCase().includes(filter.toLowerCase())
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
            <span>certs</span>
          </div>
          <h1 className="page-title">Certificates</h1>
          <p className="page-sub">
            TLS certificates for HTTP sites. Managed by Traefik Let's Encrypt.
            {/* TODO: real ACME status from Traefik acme.json (Phase 12.6) */}
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
            {filtered.length} domain{filtered.length !== 1 ? 's' : ''}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Domain</th>
              <th style={{ width: 100 }}>Status</th>
              <th>Site ID</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={3}>
                  <div className="tbl-empty">
                    <h3>{certsQ.isLoading ? 'Loading…' : 'No certificates'}</h3>
                    <p>No HTTP sites with domains are configured.</p>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.domain}</td>
                <td>
                  <Badge tone={STATUS_TONES[c.status] ?? 'neutral'}>{c.status}</Badge>
                </td>
                <td className="mono" style={{ color: 'var(--fg-3)' }}>{c.port_forward_id.slice(0, 12)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
