import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { security as secApi } from '../lib/api'
import { Badge, Button, Dialog, Field, Input, Select, Toggle } from '../components/ui'
import { useRole } from '../hooks/useRole'
import { useToast } from '../components/Toasts'
import type { Site, WafMode, AuthMode } from '../lib/types'

export default function SecurityProtections() {
  const [selected, setSelected] = useState<Site | null>(null)
  const { canMutate } = useRole()

  const q = useQuery({
    queryKey: ['sites'],
    queryFn: secApi.sites,
    refetchInterval: 10_000,
  })

  const sites = q.data ?? []

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>security</span>
            <span className="sep">/</span>
            <span>protections</span>
          </div>
          <h1 className="page-title">Protections</h1>
          <p className="page-sub">Per-site edge rules: WAF mode, rate-limiting, auth, geo-block, anti-bot.</p>
        </div>
      </div>

      {q.isLoading && <div style={{ padding: 24, color: 'var(--fg-3)' }}>Loading…</div>}

      <div style={{ display: 'grid', gap: 10, marginTop: 8 }}>
        {sites.length === 0 && !q.isLoading && (
          <div className="card">
            <div style={{ padding: 24, color: 'var(--fg-3)', fontSize: 13 }}>
              No HTTP sites configured. Add a site first.
            </div>
          </div>
        )}
        {sites.map((s) => (
          <ProtectionRow
            key={s.id}
            site={s}
            canMutate={canMutate}
            onEdit={() => setSelected(s)}
          />
        ))}
      </div>

      {selected && (
        <EditProtectionDialog
          site={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}

function ProtectionRow({
  site,
  canMutate,
  onEdit,
}: {
  site: Site
  canMutate: boolean
  onEdit: () => void
}) {
  const cfg = site.edge_config
  const wafMode: WafMode = cfg?.waf_mode ?? 'off'

  return (
    <div className="card">
      <div className="card-head">
        <div className="title mono">{site.domain ?? site.id.slice(0, 12)}</div>
        <div className="row" style={{ gap: 8 }}>
          <Badge tone={wafMode === 'block' ? 'ok' : wafMode === 'observe' ? 'warn' : 'neutral'}>
            WAF: {wafMode}
          </Badge>
          {canMutate && (
            <Button size="sm" variant="ghost" onClick={onEdit}>
              edit
            </Button>
          )}
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, padding: '12px 14px' }}>
        <ProtectionChip label="Rate-limit" active={!!cfg?.rate_limit_rps} detail={cfg?.rate_limit_rps ? `${cfg.rate_limit_rps} rps` : undefined} />
        <ProtectionChip label="Anti-bot" active={!!cfg?.antibot} />
        <ProtectionChip label="Auth" active={cfg?.auth_mode !== 'none' && !!cfg?.auth_mode} detail={cfg?.auth_mode} />
        <ProtectionChip label="IP Allow" active={!!(cfg?.ip_allow?.length)} detail={cfg?.ip_allow?.length ? `${cfg.ip_allow.length} entries` : undefined} />
        <ProtectionChip label="Geo-block" active={!!(cfg?.geo_block?.length)} detail={cfg?.geo_block?.join(', ')} />
      </div>
    </div>
  )
}

function ProtectionChip({
  label,
  active,
  detail,
}: {
  label: string
  active: boolean
  detail?: string | null
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        {label}
      </div>
      <Badge tone={active ? 'accent' : 'neutral'}>{active ? (detail ?? 'on') : 'off'}</Badge>
    </div>
  )
}

function EditProtectionDialog({ site, onClose }: { site: Site; onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const cfg = site.edge_config

  const [wafMode, setWafMode] = useState<WafMode>(cfg?.waf_mode ?? 'off')
  const [rateLimitRps, setRateLimitRps] = useState<string>(cfg?.rate_limit_rps ? String(cfg.rate_limit_rps) : '')
  const [rateLimitBurst, setRateLimitBurst] = useState<string>(cfg?.rate_limit_burst ? String(cfg.rate_limit_burst) : '')
  const [antibot, setAntibot] = useState<boolean>(cfg?.antibot ?? false)
  const [authMode, setAuthMode] = useState<AuthMode>(cfg?.auth_mode ?? 'none')
  const [geoBlock, setGeoBlock] = useState<string>(cfg?.geo_block?.join(', ') ?? '')

  const update = useMutation({
    mutationFn: () =>
      secApi.updateSite(site.id, {
        waf_mode: wafMode,
        rate_limit_rps: rateLimitRps ? Number(rateLimitRps) : null,
        rate_limit_burst: rateLimitBurst ? Number(rateLimitBurst) : null,
        antibot,
        auth_mode: authMode,
        geo_block: geoBlock ? geoBlock.split(',').map((s) => s.trim()).filter(Boolean) : null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sites'] })
      push('protections updated', 'ok', 'security://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'security://'),
  })

  return (
    <Dialog
      title="Edit protections"
      scheme={site.domain ?? site.id.slice(0, 12)}
      onClose={onClose}
      width={480}
      footer={
        <>
          <span className="left" />
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={() => update.mutate()} disabled={update.isPending}>
              {update.isPending ? 'saving…' : 'Save'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <Field label="WAF mode" hint="off = pass-through, observe = log only, block = active CrowdSec AppSec">
          <Select value={wafMode} onChange={(e) => setWafMode(e.target.value as WafMode)}>
            <option value="off">Offline</option>
            <option value="observe">Observe</option>
            <option value="block">Defense (block)</option>
          </Select>
        </Field>
        <Field label="Rate limit (req/s)" hint="0 or blank to disable">
          <Input
            type="number"
            value={rateLimitRps}
            onChange={(e) => setRateLimitRps(e.target.value)}
            placeholder="e.g. 100"
            mono
          />
        </Field>
        <Field label="Rate limit burst" hint="Burst allowance above rps">
          <Input
            type="number"
            value={rateLimitBurst}
            onChange={(e) => setRateLimitBurst(e.target.value)}
            placeholder="e.g. 50"
            mono
          />
        </Field>
        <Field label="Anti-bot (CrowdSec captcha)">
          <div className="row" style={{ gap: 10 }}>
            <Toggle on={antibot} onChange={setAntibot} />
            <span style={{ fontSize: 12, color: 'var(--fg-2)' }}>{antibot ? 'enabled' : 'disabled'}</span>
          </div>
        </Field>
        <Field label="Auth mode" hint="none = no auth, basic = HTTP BasicAuth, forward = ForwardAuth">
          <Select value={authMode} onChange={(e) => setAuthMode(e.target.value as AuthMode)}>
            <option value="none">None</option>
            <option value="basic">Basic auth</option>
            <option value="forward">Forward auth</option>
          </Select>
        </Field>
        <Field label="Geo-block" hint="Comma-separated ISO 3166-1 alpha-2 country codes to block">
          <Input
            value={geoBlock}
            onChange={(e) => setGeoBlock(e.target.value)}
            placeholder="CN, RU, KP"
            mono
          />
        </Field>
      </div>
    </Dialog>
  )
}
