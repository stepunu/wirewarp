import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { vpnEndpoints as vpnEndpointsApi } from '../lib/api'
import { Button, Field, Input, Select, Sheet } from './ui'
import type {
  VpnEndpoint,
  VpnPermission,
  VpnPermissionInput,
  VpnProtocol,
  VpnUserPermissions,
} from '../lib/types'

const PROTOCOLS: VpnProtocol[] = ['any', 'tcp', 'udp', 'icmp']

/** Per-(user, endpoint) permissions editor. Lists every vpn_enabled
 * user with their permission set on this endpoint and lets an
 * admin/operator add, edit, or remove rules per user. Save triggers a
 * `PUT /api/vpn-endpoints/{eid}/users/{uid}/permissions` which
 * atomically replaces the rule set for that user on this endpoint and
 * walks every device profile they have on the endpoint to reapply
 * iptables on the gateway.
 *
 * Permissions can be set BEFORE the user creates any device profile —
 * that's the intended pre-provisioning flow. The self-serve `My VPN`
 * page refuses profile creation if no rules exist for that user yet. */
export function VpnPermissionsSheet({
  endpoint,
  onClose,
}: {
  endpoint: VpnEndpoint
  onClose: () => void
}) {
  const sheetQ = useQuery({
    queryKey: ['vpn-endpoint-permissions', endpoint.id],
    queryFn: () => vpnEndpointsApi.listPermissions(endpoint.id),
  })

  return (
    <Sheet onClose={onClose} width={760}>
      <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
          <h2 style={{ margin: 0 }}>Permissions</h2>
          <span className="scheme">{endpoint.public_endpoint}</span>
        </div>
        <p className="sub" style={{ marginTop: 4 }}>
          Per-user rules on this endpoint. Each rule grants the user's
          devices access to a destination on the gateway's LAN. Set
          permissions BEFORE the user creates a profile — the rules are
          inherited at profile-create time and pushed to the gateway's
          iptables on save.
        </p>
        {sheetQ.isLoading && <p className="sub">Loading…</p>}
        {sheetQ.data?.length === 0 && (
          <p className="sub">
            No <code>vpn_enabled</code> users yet — flip the toggle on the Users page
            (local users) or add a member to the configured VPN group (LDAP / OIDC).
          </p>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>
          {(sheetQ.data ?? []).map((row) => (
            <UserPermissionsEditor
              key={row.user_id}
              endpoint={endpoint}
              row={row}
            />
          ))}
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 24 }}>
          <Button onClick={onClose}>Close</Button>
        </div>
      </div>
    </Sheet>
  )
}

function UserPermissionsEditor({
  endpoint,
  row,
}: {
  endpoint: VpnEndpoint
  row: VpnUserPermissions
}) {
  const qc = useQueryClient()
  const [rules, setRules] = useState<VpnPermissionInput[]>(() =>
    fromExisting(row.permissions),
  )
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState<null | 'ok' | 'err'>(null)

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRules(fromExisting(row.permissions))
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDirty(false)
  }, [row.user_id, row.permissions])

  const saveM = useMutation({
    mutationFn: () => {
      const expanded = expandDestinations(rules)
      // Reflect the expansion back in the editor so admins see the rows
      // they're about to submit (and the server response after save
      // matches the visible state).
      if (expanded.length !== rules.length) {
        setRules(expanded)
      }
      return vpnEndpointsApi.setUserPermissions(endpoint.id, row.user_id, expanded)
    },
    onSuccess: () => {
      setSaved('ok')
      setDirty(false)
      qc.invalidateQueries({ queryKey: ['vpn-endpoint-permissions', endpoint.id] })
      setTimeout(() => setSaved(null), 2000)
    },
    onError: () => setSaved('err'),
  })

  function patch(idx: number, p: Partial<VpnPermissionInput>) {
    setRules((rs) => rs.map((r, i) => (i === idx ? { ...r, ...p } : r)))
    setDirty(true)
  }
  function addRule() {
    setRules((rs) => [
      ...rs,
      { destination: '', protocol: 'any', port_range_start: null, port_range_end: null },
    ])
    setDirty(true)
  }
  function removeRule(idx: number) {
    setRules((rs) => rs.filter((_, i) => i !== idx))
    setDirty(true)
  }

  return (
    <div className="card" style={{ padding: 16 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <strong>{row.username}</strong>{' '}
          <span className="scheme" style={{ marginLeft: 8 }}>
            {row.auth_provider} · {row.profile_count} profile{row.profile_count === 1 ? '' : 's'}
          </span>
        </div>
        <span style={{ color: 'var(--fg-3)', fontSize: 11 }}>
          {row.user_id.slice(0, 8)}
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12 }}>
        {rules.map((r, idx) => (
          <RuleRow
            key={idx}
            rule={r}
            onChange={(p) => patch(idx, p)}
            onRemove={() => removeRule(idx)}
          />
        ))}
        {rules.length === 0 && (
          <p className="sub" style={{ margin: 0 }}>
            No rules — user can't access anything yet. Add one below.
          </p>
        )}
      </div>
      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          justifyContent: 'flex-end',
          marginTop: 12,
        }}
      >
        {saved === 'ok' && (
          <span style={{ color: 'var(--ok)', fontSize: 11 }}>
            saved · gateway updated
          </span>
        )}
        {saved === 'err' && (
          <span style={{ color: 'var(--err)', fontSize: 11 }}>save failed</span>
        )}
        <Button size="sm" variant="ghost" onClick={addRule}>
          + Rule
        </Button>
        <Button
          size="sm"
          variant="primary"
          disabled={!dirty || saveM.isPending}
          onClick={() => saveM.mutate()}
        >
          {saveM.isPending ? 'saving…' : 'Save'}
        </Button>
      </div>
    </div>
  )
}

function RuleRow({
  rule,
  onChange,
  onRemove,
}: {
  rule: VpnPermissionInput
  onChange: (p: Partial<VpnPermissionInput>) => void
  onRemove: () => void
}) {
  const portsApply = rule.protocol === 'tcp' || rule.protocol === 'udp'
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1.6fr 110px 90px 90px 28px',
        gap: 6,
        alignItems: 'end',
      }}
    >
      <Field
        label="Destination"
        hint="IP or CIDR (e.g. 192.168.1.50 or 192.168.2.0/24). Multiple comma- or space-separated entries are split into separate rules on save."
      >
        <Input
          mono
          value={rule.destination}
          onChange={(e) => onChange({ destination: e.target.value })}
          placeholder="192.168.1.50"
        />
      </Field>
      <Field label="Protocol">
        <Select
          value={rule.protocol}
          onChange={(e) =>
            onChange({
              protocol: e.target.value as VpnProtocol,
              ...(e.target.value === 'icmp' || e.target.value === 'any'
                ? { port_range_start: null, port_range_end: null }
                : {}),
            })
          }
        >
          {PROTOCOLS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Port from">
        <Input
          mono
          type="number"
          min={1}
          max={65535}
          disabled={!portsApply}
          value={rule.port_range_start ?? ''}
          onChange={(e) =>
            onChange({
              port_range_start: e.target.value ? parseInt(e.target.value, 10) : null,
            })
          }
        />
      </Field>
      <Field label="Port to">
        <Input
          mono
          type="number"
          min={1}
          max={65535}
          disabled={!portsApply}
          value={rule.port_range_end ?? ''}
          onChange={(e) =>
            onChange({
              port_range_end: e.target.value ? parseInt(e.target.value, 10) : null,
            })
          }
          placeholder="(same)"
        />
      </Field>
      <Button size="sm" variant="ghost" type="button" title="Remove rule" onClick={onRemove}>
        ×
      </Button>
    </div>
  )
}

function fromExisting(perms: VpnPermission[]): VpnPermissionInput[] {
  return perms.map((p) => ({
    destination: p.destination,
    protocol: p.protocol,
    port_range_start: p.port_range_start,
    port_range_end: p.port_range_end,
  }))
}

/** Expand any rule whose destination field contains multiple comma- or
 * whitespace-separated entries into one rule per entry. Each row in the
 * `vpn_permissions` table must hold a single CIDR — the agent's
 * validator rejects joined strings, breaking peer setup. */
function expandDestinations(rules: VpnPermissionInput[]): VpnPermissionInput[] {
  const out: VpnPermissionInput[] = []
  for (const r of rules) {
    const parts = (r.destination ?? '')
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (parts.length <= 1) {
      out.push({ ...r, destination: parts[0] ?? '' })
      continue
    }
    for (const p of parts) {
      out.push({ ...r, destination: p })
    }
  }
  return out
}
