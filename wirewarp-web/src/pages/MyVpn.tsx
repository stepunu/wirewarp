import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import {
  vpnEndpoints as vpnEndpointsApi,
  vpnProfiles as vpnProfilesApi,
} from '../lib/api'
import { Button, Field, Input, Select, relTime } from '../components/ui'
import { useRole } from '../hooks/useRole'
import type {
  VpnEndpoint,
  VpnProfile,
  VpnProfileIssued,
  VpnTunnelMode,
} from '../lib/types'

const MODES: VpnTunnelMode[] = ['split', 'full']

export default function MyVpn() {
  const { user } = useRole()
  const qc = useQueryClient()

  const profilesQ = useQuery({
    queryKey: ['my-vpn-profiles'],
    queryFn: vpnProfilesApi.listMine,
    enabled: !!user?.vpn_enabled,
  })
  const endpointsQ = useQuery({
    queryKey: ['vpn-endpoints'],
    queryFn: vpnEndpointsApi.list,
    enabled: !!user?.vpn_enabled,
  })

  const [issued, setIssued] = useState<VpnProfileIssued | null>(null)

  const regenerateM = useMutation({
    mutationFn: (id: string) => vpnProfilesApi.regenerateMine(id),
    onSuccess: (data) => {
      setIssued(data)
      qc.invalidateQueries({ queryKey: ['my-vpn-profiles'] })
    },
  })
  const deleteM = useMutation({
    mutationFn: (id: string) => vpnProfilesApi.deleteMine(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['my-vpn-profiles'] }),
  })

  if (!user) {
    return (
      <div className="page">
        <p className="sub">Loading…</p>
      </div>
    )
  }

  if (!user.vpn_enabled) {
    return (
      <div className="page">
        <header className="page-head">
          <div>
            <h1>My VPN</h1>
          </div>
        </header>
        <div className="card" style={{ padding: 16 }}>
          <p className="sub">
            VPN access isn't enabled for your account. Ask an admin (local user)
            or your IdP administrator (LDAP / OIDC group membership).
          </p>
        </div>
      </div>
    )
  }

  const endpoints = endpointsQ.data ?? []
  const profiles = profilesQ.data ?? []

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>My VPN</h1>
          <p className="sub">
            Add a profile per device. The .conf is shown once on creation —
            save it or scan the QR code on your phone immediately.
          </p>
        </div>
      </header>

      <CreateProfileCard
        endpoints={endpoints}
        onCreated={(data) => {
          setIssued(data)
          qc.invalidateQueries({ queryKey: ['my-vpn-profiles'] })
        }}
      />

      <div className="tbl-wrap" style={{ marginTop: 16 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Label</th>
              <th>Endpoint</th>
              <th>Tunnel IP</th>
              <th>Mode</th>
              <th>Last handshake</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {profiles.map((p) => (
              <ProfileRow
                key={p.id}
                profile={p}
                endpoint={endpoints.find((e) => e.id === p.vpn_endpoint_id)}
                onRegenerate={() => {
                  if (
                    confirm(
                      `Regenerate keys for ${p.label}? The current .conf will stop working.`,
                    )
                  ) {
                    regenerateM.mutate(p.id)
                  }
                }}
                onDelete={() => {
                  if (confirm(`Delete profile ${p.label}?`)) {
                    deleteM.mutate(p.id)
                  }
                }}
              />
            ))}
            {profiles.length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--fg-3)', padding: 24 }}>
                  No profiles yet — create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {issued && <IssuedDialog issued={issued} onClose={() => setIssued(null)} />}
    </div>
  )
}

function ProfileRow({
  profile,
  endpoint,
  onRegenerate,
  onDelete,
}: {
  profile: VpnProfile
  endpoint: VpnEndpoint | undefined
  onRegenerate: () => void
  onDelete: () => void
}) {
  return (
    <tr>
      <td><strong>{profile.label}</strong></td>
      <td>
        <code>{endpoint?.public_endpoint ?? endpoint?.id.slice(0, 8) ?? '?'}</code>
      </td>
      <td><code>{profile.tunnel_ip}</code></td>
      <td>{profile.tunnel_mode}</td>
      <td>
        {profile.last_handshake_at ? relTime(profile.last_handshake_at) : 'never'}
      </td>
      <td>
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          <Button size="sm" variant="ghost" onClick={onRegenerate}>
            Regenerate
          </Button>
          <Button size="sm" variant="danger" onClick={onDelete}>
            Delete
          </Button>
        </div>
      </td>
    </tr>
  )
}

function CreateProfileCard({
  endpoints,
  onCreated,
}: {
  endpoints: VpnEndpoint[]
  onCreated: (issued: VpnProfileIssued) => void
}) {
  const [open, setOpen] = useState(false)
  const [endpointId, setEndpointId] = useState('')
  const [label, setLabel] = useState('')
  const [mode, setMode] = useState<VpnTunnelMode>('full')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const enabledEndpoints = endpoints.filter((e) => e.enabled)

  async function go(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const issued = await vpnProfilesApi.createMine({
        vpn_endpoint_id: endpointId,
        label,
        tunnel_mode: mode,
      })
      onCreated(issued)
      setOpen(false)
      setEndpointId('')
      setLabel('')
      setMode('full')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <Button
        variant="primary"
        onClick={() => setOpen(true)}
        disabled={enabledEndpoints.length === 0}
      >
        + New profile
        {enabledEndpoints.length === 0 && (
          <span style={{ marginLeft: 8, color: 'var(--fg-3)', fontSize: 11 }}>
            (no enabled endpoints — ask an admin)
          </span>
        )}
      </Button>
    )
  }

  return (
    <form className="card" style={{ padding: 16 }} onSubmit={go}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 130px', gap: 12 }}>
        <Field label="Endpoint">
          <select
            className="select"
            value={endpointId}
            onChange={(e) => setEndpointId(e.target.value)}
            required
          >
            <option value="">Select…</option>
            {enabledEndpoints.map((e) => (
              <option key={e.id} value={e.id}>
                {e.public_endpoint}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Label" hint="Free-form name. Common: phone, work-laptop.">
          <Input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            required
            autoFocus
            maxLength={64}
          />
        </Field>
        <Field
          label="Mode"
          hint="Split = only permitted destinations. Full = all traffic via gateway (privacy / hostile WiFi)."
        >
          <Select value={mode} onChange={(e) => setMode(e.target.value as VpnTunnelMode)}>
            {MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      {error && <div style={{ marginTop: 12, color: 'var(--err)' }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}>
        <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={busy || !endpointId || !label}>
          {busy ? 'creating…' : 'Create'}
        </Button>
      </div>
    </form>
  )
}

function IssuedDialog({
  issued,
  onClose,
}: {
  issued: VpnProfileIssued
  onClose: () => void
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    QRCode.toCanvas(
      canvas,
      issued.config_text,
      { width: 240, margin: 1, color: { dark: '#000000ff', light: '#ffffffff' } },
      () => {},
    )
  }, [issued.config_text])

  function downloadConf() {
    const blob = new Blob([issued.config_text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${issued.label.replace(/[^a-z0-9_-]/gi, '_') || 'wireguard'}.conf`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.7)',
        zIndex: 200,
        display: 'grid',
        placeItems: 'center',
      }}
      onClick={onClose}
    >
      <div
        className="card"
        style={{ padding: 24, maxWidth: 720, width: '95%' }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 style={{ marginTop: 0 }}>Profile ready — save now</h2>
        <p className="sub" style={{ marginBottom: 16 }}>
          The private key is shown <strong>once</strong>. The server keeps only
          the public key + PSK; we cannot recover this if you close this dialog
          without saving. Scan the QR on your phone or download the .conf for
          your laptop.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <canvas
              ref={canvasRef}
              style={{
                background: 'var(--bg-2)',
                borderRadius: 'var(--r-2)',
                padding: 8,
              }}
            />
            <Button variant="primary" onClick={downloadConf}>
              Download .conf
            </Button>
          </div>
          <pre
            style={{
              background: 'var(--bg-2)',
              padding: 12,
              borderRadius: 'var(--r-2)',
              overflow: 'auto',
              maxHeight: 300,
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              margin: 0,
            }}
          >
            {issued.config_text}
          </pre>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
          <Button onClick={onClose}>I've saved it — close</Button>
        </div>
      </div>
    </div>
  )
}
