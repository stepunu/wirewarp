import type { WgPeerSnapshot } from '../lib/types'
import { Badge } from './ui'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function handshakeLabel(age: number | null | undefined): string {
  if (age == null) return 'never'
  if (age < 60) return `${age}s`
  if (age < 3600) return `${Math.floor(age / 60)}m`
  if (age < 86400) return `${Math.floor(age / 3600)}h`
  return `${Math.floor(age / 86400)}d`
}

// Status colour follows wg-easy: handshake < 3min = ok, < 15min = warn,
// older or never = err. Reads `handshake_age_seconds` (computed field
// from the server) rather than diffing client-side clock — server time
// is authoritative because the heartbeat could be old too.
function handshakeTone(age: number | null | undefined): 'ok' | 'warn' | 'err' {
  if (age == null) return 'err'
  if (age < 180) return 'ok'
  if (age < 900) return 'warn'
  return 'err'
}

function shortKey(pk: string): string {
  return pk.length > 14 ? `${pk.slice(0, 14)}…` : pk
}

export function WgPeerTable({ peers }: { peers: WgPeerSnapshot[] }) {
  if (peers.length === 0) {
    return (
      <div className="tbl-empty" style={{ padding: '24px 14px' }}>
        <h3>No peers</h3>
        <p>No active WireGuard peers on this interface yet.</p>
      </div>
    )
  }
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th style={{ width: 70 }}>Handshake</th>
            <th style={{ width: 80 }}>Iface</th>
            <th>Public key</th>
            <th>Endpoint</th>
            <th>Allowed IPs</th>
            <th style={{ width: 90 }}>RX</th>
            <th style={{ width: 90 }}>TX</th>
            <th style={{ width: 80 }}>Keepalive</th>
          </tr>
        </thead>
        <tbody>
          {peers.map((p) => {
            const tone = handshakeTone(p.handshake_age_seconds)
            return (
              <tr key={p.id}>
                <td>
                  <Badge tone={tone}>{handshakeLabel(p.handshake_age_seconds)}</Badge>
                </td>
                <td className="mono">{p.interface}</td>
                <td className="mono" title={p.public_key}>
                  {shortKey(p.public_key)}
                </td>
                <td className="mono" style={{ color: 'var(--fg-2)' }}>
                  {p.endpoint || '—'}
                </td>
                <td className="mono" style={{ color: 'var(--fg-2)' }}>
                  {p.allowed_ips || '—'}
                </td>
                <td className="mono" style={{ color: 'var(--fg-1)' }}>{formatBytes(p.rx_bytes)}</td>
                <td className="mono" style={{ color: 'var(--fg-1)' }}>{formatBytes(p.tx_bytes)}</td>
                <td className="mono" style={{ color: 'var(--fg-3)' }}>
                  {p.persistent_keepalive ? `${p.persistent_keepalive}s` : '—'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
