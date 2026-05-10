import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth, setToken } from '../lib/api'
import type { AuthProvider } from '../lib/types'
import { Button, Field, Input } from '../components/ui'
import { Ic } from '../components/icons'

type Mode = AuthProvider

export default function Login() {
  const navigate = useNavigate()
  const [active, setActive] = useState<AuthProvider | null>(null)
  // Operator can always fall back to local creds (break-glass) even when
  // the active IdP is OIDC/LDAP — toggled by clicking "Use local account".
  const [mode, setMode] = useState<Mode>('local')
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    auth
      .providers()
      .then((r) => {
        setActive(r.active_provider)
        setMode(r.active_provider)
      })
      .catch(() => {
        setActive('local')
        setMode('local')
      })
  }, [])

  async function go(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = mode === 'ldap' ? await auth.ldapLogin(u, p) : await auth.login(u, p)
      setToken(res.access_token)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={go}>
        <div className="brand-row">
          <img className="logo" src="/logo.svg" alt="" width={28} height={28} />
          <div>
            <div style={{ color: 'var(--fg-3)', fontSize: 11 }}>wire://</div>
            <div style={{ fontWeight: 600, letterSpacing: '0.02em' }}>wirewarp</div>
          </div>
        </div>
        <h1>Sign in</h1>
        <p className="sub">
          {mode === 'oidc'
            ? 'Single sign-on via your identity provider.'
            : mode === 'ldap'
              ? 'Authenticating against the configured LDAP directory.'
              : 'Self-hosted WireGuard tunnel control plane.'}
        </p>

        {mode === 'oidc' ? (
          <Button
            variant="primary"
            size="lg"
            type="button"
            style={{ width: '100%', justifyContent: 'center' }}
            onClick={() => {
              window.location.href = '/api/auth/oidc/login'
            }}
          >
            Sign in with SSO
            <Ic.enter />
          </Button>
        ) : (
          <>
            <div className="login-fields">
              <Field label="Username">
                <Input value={u} onChange={(e) => setU(e.target.value)} autoFocus />
              </Field>
              <Field label="Password">
                <Input type="password" value={p} onChange={(e) => setP(e.target.value)} />
              </Field>
            </div>
            {error && (
              <div
                style={{
                  marginBottom: 12,
                  padding: '8px 12px',
                  border: '1px solid var(--err)',
                  background: 'var(--err-bg)',
                  color: 'var(--err)',
                  borderRadius: 'var(--r-2)',
                  fontSize: 12,
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {error}
              </div>
            )}
            <Button
              variant="primary"
              size="lg"
              style={{ width: '100%', justifyContent: 'center' }}
              type="submit"
              disabled={busy}
            >
              {busy ? 'authenticating…' : 'Sign in'}
              {!busy && <Ic.enter />}
            </Button>
          </>
        )}

        {/* Break-glass fallback: when the active provider is external, the
            operator can still sign in with a local password — required if
            the IdP is down or the operator is the bootstrap admin. */}
        {active && active !== 'local' && mode !== 'local' && (
          <button
            type="button"
            className="login-fallback"
            style={{
              marginTop: 12,
              background: 'transparent',
              border: 'none',
              color: 'var(--fg-2)',
              fontSize: 11,
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
            }}
            onClick={() => setMode('local')}
          >
            Use local account →
          </button>
        )}
        {mode === 'local' && active && active !== 'local' && (
          <button
            type="button"
            style={{
              marginTop: 12,
              background: 'transparent',
              border: 'none',
              color: 'var(--fg-2)',
              fontSize: 11,
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
            }}
            onClick={() => setMode(active)}
          >
            ← Back to {active.toUpperCase()} sign-in
          </button>
        )}

        <div className="login-foot">
          <span>self-hosted</span>
          <span>wire://control</span>
        </div>
      </form>
    </div>
  )
}
