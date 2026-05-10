import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { users as usersApi } from '../lib/api'
import { Badge, Button, Field, Input, Select, relTime } from '../components/ui'
import type { Role, User } from '../lib/types'
import { useRole } from '../hooks/useRole'

const ROLES: Role[] = ['admin', 'operator', 'viewer']

export default function Users() {
  const { user: me } = useRole()
  const qc = useQueryClient()
  const usersQ = useQuery({ queryKey: ['users'], queryFn: usersApi.list })

  const patchM = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: string
      data: { role?: Role; is_active?: boolean; vpn_enabled?: boolean }
    }) => usersApi.patch(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
  const delM = useMutation({
    mutationFn: (id: string) => usersApi.del(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Users</h1>
          <p className="sub">Local accounts plus JIT-provisioned OIDC / LDAP rows.</p>
        </div>
      </header>

      <CreateUserCard
        onCreated={() => qc.invalidateQueries({ queryKey: ['users'] })}
      />

      <div className="tbl-wrap" style={{ marginTop: 16 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Provider</th>
              <th>Role</th>
              <th>Status</th>
              <th>VPN</th>
              <th>Last login</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(usersQ.data ?? []).map((u) => (
              <UserRow
                key={u.id}
                user={u}
                isMe={me?.id === u.id}
                onChangeRole={(role) => patchM.mutate({ id: u.id, data: { role } })}
                onToggleActive={() =>
                  patchM.mutate({ id: u.id, data: { is_active: !u.is_active } })
                }
                onToggleVpn={() =>
                  patchM.mutate({ id: u.id, data: { vpn_enabled: !u.vpn_enabled } })
                }
                onDelete={() => {
                  if (confirm(`Delete user ${u.username}?`)) delM.mutate(u.id)
                }}
              />
            ))}
            {usersQ.data?.length === 0 && (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', color: 'var(--fg-3)', padding: 24 }}>
                  No users yet — create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function UserRow({
  user,
  isMe,
  onChangeRole,
  onToggleActive,
  onToggleVpn,
  onDelete,
}: {
  user: User
  isMe: boolean
  onChangeRole: (role: Role) => void
  onToggleActive: () => void
  onToggleVpn: () => void
  onDelete: () => void
}) {
  return (
    <tr>
      <td data-label="username">
        <strong>{user.username}</strong>
        {isMe && (
          <span className="scheme" style={{ marginLeft: 8, fontSize: 10 }}>
            (you)
          </span>
        )}
      </td>
      <td data-label="email">{user.email}</td>
      <td data-label="provider">
        <Badge tone={user.auth_provider === 'local' ? 'neutral' : 'info'}>
          {user.auth_provider}
        </Badge>
      </td>
      <td data-label="role">
        <Select
          value={user.role}
          onChange={(e) => onChangeRole(e.target.value as Role)}
          disabled={isMe}
          style={{ width: 110 }}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </Select>
      </td>
      <td data-label="active">
        <Badge tone={user.is_active ? 'ok' : 'warn'}>
          {user.is_active ? 'active' : 'disabled'}
        </Badge>
      </td>
      <td data-label="vpn">
        {user.auth_provider === 'local' ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={onToggleVpn}
            title="Toggle VPN portal access"
          >
            {user.vpn_enabled ? 'on' : 'off'}
          </Button>
        ) : (
          <Badge tone={user.vpn_enabled ? 'ok' : 'neutral'}>
            {user.vpn_enabled ? 'on (idp)' : 'off (idp)'}
          </Badge>
        )}
      </td>
      <td data-label="last login">{user.last_login_at ? relTime(user.last_login_at) : '—'}</td>
      <td data-label="">
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          <Button size="sm" variant="ghost" onClick={onToggleActive} disabled={isMe}>
            {user.is_active ? 'Disable' : 'Enable'}
          </Button>
          <Button size="sm" variant="danger" onClick={onDelete} disabled={isMe}>
            Delete
          </Button>
        </div>
      </td>
    </tr>
  )
}

function CreateUserCard({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function go(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await usersApi.create({ username, email, password, role })
      onCreated()
      setUsername('')
      setEmail('')
      setPassword('')
      setRole('viewer')
      setOpen(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <Button onClick={() => setOpen(true)} variant="primary">
        + Create local user
      </Button>
    )
  }

  return (
    <form className="card" style={{ padding: 16 }} onSubmit={go}>
      <div className="row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 130px', gap: 12 }}>
        <Field label="Username">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
        </Field>
        <Field label="Email">
          <Input value={email} onChange={(e) => setEmail(e.target.value)} required type="email" />
        </Field>
        <Field label="Password">
          <Input value={password} onChange={(e) => setPassword(e.target.value)} required type="password" minLength={8} />
        </Field>
        <Field label="Role">
          <Select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}>
        <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={busy}>
          {busy ? 'creating…' : 'Create'}
        </Button>
      </div>
    </form>
  )
}
