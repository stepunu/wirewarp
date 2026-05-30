import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settings as settingsApi } from '../lib/api'
import { Button, Field, Input, Select, Tabs } from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'
import type {
  AuthProvider,
  LdapConfig,
  OidcConfig,
  Role,
} from '../lib/types'

type Tab = 'general' | 'auth' | 'appearance'

export default function Settings() {
  const [tab, setTab] = useState<Tab>('general')
  const [theme, setTheme] = useState<'dark' | 'light'>(
    (localStorage.getItem('theme') as 'dark' | 'light') || 'dark',
  )

  function applyTheme(t: 'dark' | 'light') {
    setTheme(t)
    document.documentElement.dataset.theme = t
    localStorage.setItem('theme', t)
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>settings</span>
          </div>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Instance configuration and dashboard appearance.</p>
        </div>
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'general', label: 'General' },
          { value: 'auth', label: 'Authentication' },
          { value: 'appearance', label: 'Appearance' },
        ]}
      />

      {tab === 'general' && <GeneralTab />}
      {tab === 'auth' && <AuthTab />}

      {tab === 'appearance' && (
        <div className="card">
          <div className="card-body">
            <div className="settings-row">
              <div>
                <div style={{ fontWeight: 500 }}>Theme</div>
                <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
                  Dark is default. Light is supported but secondary.
                </div>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <Button
                  variant={theme === 'dark' ? 'primary' : 'default'}
                  leading={<Ic.moon />}
                  onClick={() => applyTheme('dark')}
                >
                  Dark
                </Button>
                <Button
                  variant={theme === 'light' ? 'primary' : 'default'}
                  leading={<Ic.sun />}
                  onClick={() => applyTheme('light')}
                >
                  Light
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function GeneralTab() {
  const qc = useQueryClient()
  const push = useToast()
  const dataQ = useQuery({ queryKey: ['settings'], queryFn: settingsApi.get })
  const [publicUrl, setPublicUrl] = useState('')
  const [internalUrl, setInternalUrl] = useState('')
  const [instanceName, setInstanceName] = useState('')
  const [tokenExpiry, setTokenExpiry] = useState(24)
  const [dnsProvider, setDnsProvider] = useState<string>('')
  const [cfToken, setCfToken] = useState('')
  const [captchaProvider, setCaptchaProvider] = useState('')
  const [captchaSiteKey, setCaptchaSiteKey] = useState('')
  const [captchaSecretKey, setCaptchaSecretKey] = useState('')

  useEffect(() => {
    if (!dataQ.data) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setPublicUrl(dataQ.data.public_url ?? '')
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setInternalUrl(dataQ.data.internal_url ?? '')
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setInstanceName(dataQ.data.instance_name)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTokenExpiry(dataQ.data.agent_token_expiry_hours)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDnsProvider(dataQ.data.dns_provider ?? '')
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setCaptchaProvider(dataQ.data.captcha_provider ?? '')
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setCaptchaSiteKey(dataQ.data.captcha_site_key ?? '')
    // Token field stays empty on load — only writes when the operator
    // types something. We never round-trip the actual token value.
  }, [dataQ.data])

  const update = useMutation({
    mutationFn: () => {
      const payload: Record<string, unknown> = {
        public_url: publicUrl.trim() || null,
        internal_url: internalUrl.trim() || null,
        instance_name: instanceName.trim() || undefined,
        agent_token_expiry_hours: tokenExpiry,
        dns_provider: dnsProvider || null,
        captcha_provider: captchaProvider || null,
        captcha_site_key: captchaProvider ? captchaSiteKey.trim() || null : null,
      }
      // Only send cloudflare_api_token if the operator typed a new one.
      // Empty string means "keep existing".
      if (cfToken.trim()) payload.cloudflare_api_token = cfToken.trim()
      if (captchaSecretKey.trim()) payload.captcha_secret_key = captchaSecretKey.trim()
      return settingsApi.update(payload)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      setCfToken('')
      setCaptchaSecretKey('')
      push('settings saved', 'ok', 'settings://')
    },
    onError: (e: Error) => push(e.message, 'err', 'settings://'),
  })

  return (
    <div className="card">
      <div className="card-body">
        <div className="settings-row" style={{ padding: '8px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Instance</div>
            <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
              How this WireWarp instance presents itself.
            </div>
          </div>
          <div className="col" style={{ gap: 12, maxWidth: 480 }}>
            <Field label="Instance name">
              <Input value={instanceName} onChange={(e) => setInstanceName(e.target.value)} placeholder="WireWarp" />
            </Field>
            <Field label="Public URL" hint="Used by external/VPS agents to phone home. Must be reachable from the internet.">
              <Input
                mono
                value={publicUrl}
                onChange={(e) => setPublicUrl(e.target.value)}
                placeholder="http://ddns.example.com:8100"
              />
            </Field>
            <Field label="Internal URL" hint="Used by LAN gateway agents. Direct LAN IP avoids split-DNS. Falls back to Public URL.">
              <Input
                mono
                value={internalUrl}
                onChange={(e) => setInternalUrl(e.target.value)}
                placeholder="http://192.168.1.100:8100"
              />
            </Field>
          </div>
        </div>
        <div className="hr" />
        <div className="settings-row" style={{ padding: '8px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Anti-bot CAPTCHA</div>
            <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
              Provider keys used when a Security Edge site enables CrowdSec CAPTCHA remediation.
            </div>
          </div>
          <div className="col" style={{ gap: 12, maxWidth: 480 }}>
            <Field label="Provider">
              <Select value={captchaProvider} onChange={(e) => setCaptchaProvider(e.target.value)}>
                <option value="">disabled</option>
                <option value="hcaptcha">hCaptcha</option>
                <option value="recaptcha">reCAPTCHA</option>
                <option value="turnstile">Turnstile</option>
              </Select>
            </Field>
            {captchaProvider && (
              <>
                <Field label="Site key">
                  <Input
                    mono
                    value={captchaSiteKey}
                    onChange={(e) => setCaptchaSiteKey(e.target.value)}
                    placeholder="site key"
                  />
                </Field>
                <Field
                  label={
                    dataQ.data?.captcha_secret_key_set
                      ? 'Secret key (saved — leave blank to keep, type to replace)'
                      : 'Secret key'
                  }
                >
                  <Input
                    mono
                    type="password"
                    value={captchaSecretKey}
                    onChange={(e) => setCaptchaSecretKey(e.target.value)}
                    placeholder={dataQ.data?.captcha_secret_key_set ? '••••••••' : 'secret key'}
                  />
                </Field>
              </>
            )}
          </div>
        </div>
        <div className="hr" />
        <div className="settings-row" style={{ padding: '8px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Agent registration</div>
            <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
              Default token expiry for new agents.
            </div>
          </div>
          <div className="col" style={{ gap: 12, maxWidth: 480 }}>
            <Field label="Token expiry (hours)">
              <Input
                type="number"
                mono
                value={tokenExpiry}
                onChange={(e) => setTokenExpiry(parseInt(e.target.value, 10) || 0)}
                min={1}
              />
            </Field>
          </div>
        </div>
        <div className="hr" />
        <div className="settings-row" style={{ padding: '8px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>DNS sync</div>
            <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
              Auto-update public DNS records when a LAN client's egress IP changes so
              hostnames keep resolving to a working VPS. Today only Cloudflare is
              supported as a provider — operators on other providers can leave this
              empty and use the per-LAN-client record list as documentation; they'll
              get a toast on every egress change listing the records to update by hand.
            </div>
          </div>
          <div className="col" style={{ gap: 12, maxWidth: 480 }}>
            <Field label="Provider">
              <select
                value={dnsProvider}
                onChange={(e) => setDnsProvider(e.target.value)}
                style={{ width: '100%' }}
              >
                <option value="">manual (no sync)</option>
                <option value="cloudflare">Cloudflare</option>
              </select>
            </Field>
            {dnsProvider === 'cloudflare' && (
              <Field
                label={
                  dataQ.data?.cloudflare_token_set
                    ? 'API token (saved — leave blank to keep, type to replace)'
                    : 'API token'
                }
                hint="Cloudflare API token with Zone.DNS:Edit on the relevant zones."
              >
                <Input
                  mono
                  type="password"
                  value={cfToken}
                  onChange={(e) => setCfToken(e.target.value)}
                  placeholder={dataQ.data?.cloudflare_token_set ? '••••••••' : 'paste token here'}
                />
              </Field>
            )}
          </div>
        </div>
        <div style={{ textAlign: 'right', marginTop: 8 }}>
          <Button variant="primary" onClick={() => update.mutate()} disabled={update.isPending}>
            {update.isPending ? 'saving…' : 'Save changes'}
          </Button>
        </div>
      </div>
    </div>
  )
}


// ---- Auth tab ----------------------------------------------------------

const ROLES: Role[] = ['admin', 'operator', 'viewer']

function AuthTab() {
  const qc = useQueryClient()
  const push = useToast()
  const dataQ = useQuery({ queryKey: ['settings'], queryFn: settingsApi.get })

  const [provider, setProvider] = useState<AuthProvider>('local')
  const [oidc, setOidc] = useState<OidcConfig>({})
  const [oidcSecret, setOidcSecret] = useState('')
  const [ldap, setLdap] = useState<LdapConfig>({})
  const [ldapPw, setLdapPw] = useState('')
  const [test, setTest] = useState<{ ok: boolean; detail: string } | null>(null)

  useEffect(() => {
    if (!dataQ.data) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setProvider(dataQ.data.auth_provider)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOidc(dataQ.data.oidc_config ?? {})
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLdap(dataQ.data.ldap_config ?? {})
  }, [dataQ.data])

  const save = useMutation({
    mutationFn: () => {
      const oidcPayload: OidcConfig | undefined =
        provider === 'oidc' ? { ...oidc } : undefined
      if (oidcPayload && oidcSecret.trim()) oidcPayload.client_secret = oidcSecret.trim()

      const ldapPayload: LdapConfig | undefined =
        provider === 'ldap' ? { ...ldap } : undefined
      if (ldapPayload && ldapPw.trim()) ldapPayload.bind_password = ldapPw.trim()

      return settingsApi.update({
        auth_provider: provider,
        oidc_config: oidcPayload,
        ldap_config: ldapPayload,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      setOidcSecret('')
      setLdapPw('')
      push('auth provider saved', 'ok', 'auth://')
    },
    onError: (e: Error) => push(e.message, 'err', 'auth://'),
  })

  async function runTest() {
    setTest(null)
    try {
      const cfg =
        provider === 'oidc'
          ? { ...oidc, client_secret: oidcSecret || undefined }
          : provider === 'ldap'
            ? { ...ldap, bind_password: ldapPw || undefined }
            : null
      const r = await settingsApi.testAuthConnection(provider, cfg ?? undefined)
      setTest(r)
    } catch (e) {
      setTest({ ok: false, detail: e instanceof Error ? e.message : 'unknown error' })
    }
  }

  return (
    <div className="card">
      <div className="card-body">
        <div className="settings-row" style={{ padding: '8px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Active provider</div>
            <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
              Pick one external IdP. Local-account login is always available as a
              break-glass fallback (the sign-in page links to it).
            </div>
          </div>
          <div className="col" style={{ gap: 12, maxWidth: 480 }}>
            <Field label="Provider">
              <Select
                value={provider}
                onChange={(e) => setProvider(e.target.value as AuthProvider)}
              >
                <option value="local">Local accounts only</option>
                <option value="oidc">OIDC (single sign-on)</option>
                <option value="ldap">LDAP / Active Directory</option>
              </Select>
            </Field>
          </div>
        </div>

        {provider === 'oidc' && (
          <>
            <div className="hr" />
            <OidcForm
              cfg={oidc}
              onChange={setOidc}
              secret={oidcSecret}
              onSecret={setOidcSecret}
              secretSet={!!dataQ.data?.oidc_secret_set}
            />
          </>
        )}
        {provider === 'ldap' && (
          <>
            <div className="hr" />
            <LdapForm
              cfg={ldap}
              onChange={setLdap}
              bindPw={ldapPw}
              onBindPw={setLdapPw}
              secretSet={!!dataQ.data?.ldap_secret_set}
            />
          </>
        )}

        {test && (
          <div
            style={{
              marginTop: 12,
              padding: '8px 12px',
              border: `1px solid var(--${test.ok ? 'ok' : 'err'})`,
              background: `var(--${test.ok ? 'ok' : 'err'}-bg)`,
              color: `var(--${test.ok ? 'ok' : 'err'})`,
              borderRadius: 'var(--r-2)',
              fontSize: 12,
              fontFamily: 'var(--font-mono)',
            }}
          >
            {test.ok ? '✓ ' : '✗ '}
            {test.detail}
          </div>
        )}

        <div style={{ textAlign: 'right', marginTop: 16, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          {provider !== 'local' && (
            <Button variant="ghost" onClick={runTest}>
              Test connection
            </Button>
          )}
          <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending}>
            {save.isPending ? 'saving…' : 'Save changes'}
          </Button>
        </div>
      </div>
    </div>
  )
}

function OidcForm({
  cfg,
  onChange,
  secret,
  onSecret,
  secretSet,
}: {
  cfg: OidcConfig
  onChange: (next: OidcConfig) => void
  secret: string
  onSecret: (v: string) => void
  secretSet: boolean
}) {
  function patch(p: Partial<OidcConfig>) {
    onChange({ ...cfg, ...p })
  }
  return (
    <div className="settings-row" style={{ padding: '8px 0' }}>
      <div>
        <div style={{ fontWeight: 500 }}>OIDC client</div>
        <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
          Standard OpenID Connect — works with Keycloak, Authentik, Pocket-ID,
          Microsoft Entra, Google, etc. Server runs discovery at{' '}
          <code>{'<issuer>/.well-known/openid-configuration'}</code>.
        </div>
      </div>
      <div className="col" style={{ gap: 12, maxWidth: 540 }}>
        <Field label="Issuer URL">
          <Input
            mono
            value={cfg.issuer ?? ''}
            onChange={(e) => patch({ issuer: e.target.value })}
            placeholder="https://idp.example.com/realms/main"
          />
        </Field>
        <Field label="Redirect URL" hint="Must match what's registered on the IdP. Usually https://wirewarp.example/api/auth/oidc/callback.">
          <Input
            mono
            value={cfg.redirect_url ?? ''}
            onChange={(e) => patch({ redirect_url: e.target.value })}
          />
        </Field>
        <Field label="Client ID">
          <Input
            mono
            value={cfg.client_id ?? ''}
            onChange={(e) => patch({ client_id: e.target.value })}
          />
        </Field>
        <Field label={secretSet ? 'Client secret (saved — leave blank to keep, type to replace)' : 'Client secret'}>
          <Input
            mono
            type="password"
            value={secret}
            onChange={(e) => onSecret(e.target.value)}
            placeholder={secretSet ? '••••••••' : 'paste secret'}
          />
        </Field>
        <Field label="Scopes (comma-separated)">
          <Input
            mono
            value={(cfg.scopes ?? ['openid', 'email', 'profile']).join(',')}
            onChange={(e) =>
              patch({
                scopes: e.target.value
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
          />
        </Field>
        <Field label="Role claim" hint="JWT/userinfo claim that carries group / role membership.">
          <Input
            mono
            value={cfg.role_claim ?? 'groups'}
            onChange={(e) => patch({ role_claim: e.target.value })}
          />
        </Field>
        <Field label="Default role">
          <Select
            value={cfg.default_role ?? 'viewer'}
            onChange={(e) => patch({ default_role: e.target.value as Role })}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
        <RoleMapEditor
          label="Group → role mapping"
          hint="Claim values that grant elevated roles. Highest privilege wins."
          map={cfg.claim_role_map ?? {}}
          onChange={(claim_role_map) => patch({ claim_role_map })}
        />
        <Field
          label="VPN access claim value (optional)"
          hint="If set, users carrying this claim value get a `My VPN` portal where they can self-serve WireGuard configs. Leave empty to manage VPN access manually per user."
        >
          <Input
            mono
            value={cfg.vpn_group ?? ''}
            onChange={(e) => patch({ vpn_group: e.target.value })}
            placeholder="e.g. wg-vpn"
          />
        </Field>
      </div>
    </div>
  )
}

function LdapForm({
  cfg,
  onChange,
  bindPw,
  onBindPw,
  secretSet,
}: {
  cfg: LdapConfig
  onChange: (next: LdapConfig) => void
  bindPw: string
  onBindPw: (v: string) => void
  secretSet: boolean
}) {
  function patch(p: Partial<LdapConfig>) {
    onChange({ ...cfg, ...p })
  }
  return (
    <div className="settings-row" style={{ padding: '8px 0' }}>
      <div>
        <div style={{ fontWeight: 500 }}>LDAP / AD</div>
        <div style={{ color: 'var(--fg-2)', fontSize: 12 }}>
          Bind-as-user authentication. Optional service account is used only
          to search group memberships when the user's own bind can't read
          the groups OU.
        </div>
      </div>
      <div className="col" style={{ gap: 12, maxWidth: 540 }}>
        <Field label="Server URL">
          <Input
            mono
            value={cfg.url ?? ''}
            onChange={(e) => patch({ url: e.target.value })}
            placeholder="ldaps://ldap.example.com:636"
          />
        </Field>
        <Field label="User DN template" hint="{username} is replaced at login time.">
          <Input
            mono
            value={cfg.user_dn_template ?? ''}
            onChange={(e) => patch({ user_dn_template: e.target.value })}
            placeholder="uid={username},ou=people,dc=example,dc=com"
          />
        </Field>
        <Field label="Service account DN (optional)">
          <Input
            mono
            value={cfg.bind_dn ?? ''}
            onChange={(e) => patch({ bind_dn: e.target.value })}
            placeholder="cn=svc-wirewarp,dc=example,dc=com"
          />
        </Field>
        <Field label={secretSet ? 'Service account password (saved — leave blank to keep)' : 'Service account password'}>
          <Input
            mono
            type="password"
            value={bindPw}
            onChange={(e) => onBindPw(e.target.value)}
            placeholder={secretSet ? '••••••••' : ''}
          />
        </Field>
        <Field label="Group search base">
          <Input
            mono
            value={cfg.group_search_base ?? ''}
            onChange={(e) => patch({ group_search_base: e.target.value })}
            placeholder="ou=groups,dc=example,dc=com"
          />
        </Field>
        <Field label="Default role">
          <Select
            value={cfg.default_role ?? 'viewer'}
            onChange={(e) => patch({ default_role: e.target.value as Role })}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
        <RoleMapEditor
          label="Group → role mapping"
          hint="Match by CN or full DN. Highest privilege wins."
          map={cfg.group_role_map ?? {}}
          onChange={(group_role_map) => patch({ group_role_map })}
        />
        <Field
          label="VPN access group (optional)"
          hint="LDAP group CN or DN whose members get a `My VPN` portal. Leave empty to manage VPN access manually per user."
        >
          <Input
            mono
            value={cfg.vpn_group ?? ''}
            onChange={(e) => patch({ vpn_group: e.target.value })}
            placeholder="e.g. sso_wirewarp_vpn"
          />
        </Field>
      </div>
    </div>
  )
}

function RoleMapEditor({
  label,
  hint,
  map,
  onChange,
}: {
  label: string
  hint?: string
  map: Record<string, Role>
  onChange: (next: Record<string, Role>) => void
}) {
  const entries = Object.entries(map)
  function set(key: string, role: Role) {
    onChange({ ...map, [key]: role })
  }
  function rename(oldKey: string, newKey: string) {
    if (oldKey === newKey) return
    const next: Record<string, Role> = {}
    for (const [k, v] of Object.entries(map)) next[k === oldKey ? newKey : k] = v
    onChange(next)
  }
  function remove(key: string) {
    const next = { ...map }
    delete next[key]
    onChange(next)
  }
  return (
    <Field label={label} hint={hint}>
      <div className="col" style={{ gap: 6 }}>
        {entries.map(([key, role]) => (
          <div key={key} style={{ display: 'grid', gridTemplateColumns: '1fr 110px 28px', gap: 6 }}>
            <Input
              mono
              defaultValue={key}
              onBlur={(e) => rename(key, e.target.value)}
            />
            <Select value={role} onChange={(e) => set(key, e.target.value as Role)}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </Select>
            <Button size="sm" variant="ghost" onClick={() => remove(key)} type="button" title="Remove">
              ×
            </Button>
          </div>
        ))}
        <Button
          size="sm"
          variant="ghost"
          type="button"
          onClick={() => {
            const next = { ...map }
            let i = 1
            let key = 'new-group'
            while (key in next) {
              key = `new-group-${i++}`
            }
            next[key] = 'viewer'
            onChange(next)
          }}
        >
          + Add mapping
        </Button>
      </div>
    </Field>
  )
}
