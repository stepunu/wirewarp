import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  security as secApi,
  tunnelClientAttachments as attachApi,
} from '../lib/api'
import {
  Badge,
  Button,
  Dialog,
  Field,
  FilterBar,
  Input,
  Select,
  relTime,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useRole } from '../hooks/useRole'
import { useToast } from '../components/Toasts'
import type { Site, SiteCreate, WafMode } from '../lib/types'

const WAF_TONES: Record<WafMode, 'ok' | 'warn' | 'neutral'> = {
  block: 'ok',
  observe: 'warn',
  off: 'neutral',
}

const WAF_LABELS: Record<WafMode, string> = {
  block: 'Defense',
  observe: 'Observe',
  off: 'Offline',
}

export default function SecuritySites() {
  const [filter, setFilter] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const { canMutate } = useRole()

  const q = useQuery({
    queryKey: ['sites'],
    queryFn: () => secApi.sites(),
    refetchInterval: 10_000,
  })

  const sites = q.data ?? []

  const filtered = sites.filter((s) => {
    if (!filter) return true
    const f = filter.toLowerCase()
    return [s.domain, s.description, s.destination_ip]
      .filter(Boolean)
      .some((x) => x!.toLowerCase().includes(f))
  })

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>security</span>
            <span className="sep">/</span>
            <span>sites</span>
          </div>
          <h1 className="page-title">Sites</h1>
          <p className="page-sub">HTTP services routed through Traefik WAF. Raw TCP/UDP forwards stay in Port Forwards.</p>
        </div>
        <div className="page-actions">
          {canMutate && (
            <Button variant="primary" leading={<Ic.plus />} onClick={() => setShowCreate(true)}>
              Add site
            </Button>
          )}
        </div>
      </div>

      <FilterBar
        filter={filter}
        setFilter={setFilter}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{sites.length}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Upstream</th>
              <th style={{ width: 100 }}>Run mode</th>
              <th>Features</th>
              <th style={{ width: 80 }}>State</th>
              <th style={{ width: 100 }}>Added</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="tbl-empty">
                    <h3>{q.isLoading ? 'Loading…' : 'No sites'}</h3>
                    <p>Add an HTTP site to route it through the Traefik WAF.</p>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((s) => (
              <SiteRow key={s.id} site={s} canMutate={canMutate} />
            ))}
          </tbody>
        </table>
      </div>

      {showCreate && <CreateSiteDialog onClose={() => setShowCreate(false)} />}
    </div>
  )
}

function SiteRow({ site, canMutate }: { site: Site; canMutate: boolean }) {
  const qc = useQueryClient()
  const push = useToast()
  const cfg = site.edge_config
  const wafMode: WafMode = cfg?.waf_mode ?? 'off'

  const del = useMutation({
    mutationFn: () => secApi.deleteSite(site.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sites'] })
      push('site removed', 'ok', 'security://')
    },
    onError: (e: Error) => push(e.message, 'err', 'security://'),
  })

  const toggleActive = useMutation({
    mutationFn: () => secApi.updateSite(site.id, { active: !site.active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sites'] }),
    onError: (e: Error) => push(e.message, 'err', 'security://'),
  })

  const features: string[] = []
  if (cfg?.antibot) features.push('Captcha')
  if (cfg?.auth_mode && cfg.auth_mode !== 'none') features.push('Auth')
  if (cfg?.rate_limit_rps) features.push('Rate-limit')
  if (cfg?.geo_block?.length) features.push('Geo-block')

  return (
    <tr style={{ opacity: site.active ? 1 : 0.55 }}>
      <td className="mono">{site.domain ?? '—'}</td>
      <td className="mono">{site.destination_ip}:{site.destination_port}</td>
      <td>
        <Badge tone={WAF_TONES[wafMode]}>{WAF_LABELS[wafMode]}</Badge>
      </td>
      <td>
        <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
          {features.length === 0 && (
            <span style={{ color: 'var(--fg-3)', fontSize: 12 }}>none</span>
          )}
          {features.map((f) => (
            <Badge key={f} tone="info">{f}</Badge>
          ))}
        </div>
      </td>
      <td>
        <Badge tone={site.active ? 'ok' : 'neutral'}>{site.active ? 'active' : 'off'}</Badge>
      </td>
      <td className="mono" style={{ color: 'var(--fg-3)' }}>{relTime(site.created_at)}</td>
      {canMutate && (
        <td onClick={(e) => e.stopPropagation()}>
          <div className="row-actions">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => toggleActive.mutate()}
              disabled={toggleActive.isPending}
            >
              {site.active ? 'disable' : 'enable'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              style={{ color: 'var(--err)' }}
              onClick={() => {
                if (confirm(`Remove site ${site.domain}?`)) del.mutate()
              }}
            >
              remove
            </Button>
          </div>
        </td>
      )}
    </tr>
  )
}

export function CreateSiteDialog({ onClose, onSaved }: { onClose: () => void; onSaved?: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const [domain, setDomain] = useState('')
  const [destIp, setDestIp] = useState('')
  const [destPort, setDestPort] = useState('80')
  const [wafMode, setWafMode] = useState<WafMode>('observe')
  const [attachmentId, setAttachmentId] = useState('')

  const attachQ = useQuery({
    queryKey: ['tunnel-client-attachments'],
    queryFn: () => attachApi.list(),
  })

  const create = useMutation({
    mutationFn: () => {
      const body: SiteCreate = {
        attachment_id: attachmentId,
        protocol: 'tcp',
        public_port: 443,
        destination_ip: destIp,
        destination_port: Number(destPort),
        domain,
        waf_mode: wafMode,
      }
      return secApi.createSite(body)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sites'] })
      onSaved?.()
      push('site created', 'ok', 'security://')
      onClose()
    },
    onError: (e: Error) => push(e.message, 'err', 'security://'),
  })

  return (
    <Dialog
      title="Add site"
      scheme="POST /api/security/sites"
      onClose={onClose}
      width={520}
      footer={
        <>
          <span className="left" />
          <div className="right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              onClick={() => create.mutate()}
              disabled={create.isPending || !domain || !destIp || !attachmentId}
            >
              {create.isPending ? 'creating…' : 'Create site'}
            </Button>
          </div>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <Field label="Domain" hint="Public hostname (e.g. app.example.com)">
          <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="app.example.com" />
        </Field>
        <Field label="Tunnel attachment" hint="Which tunnel client attachment this site routes through">
          <Select value={attachmentId} onChange={(e) => setAttachmentId(e.target.value)}>
            <option value="">— select —</option>
            {(attachQ.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.wg_interface} ({a.tunnel_ip})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Destination IP" hint="LAN IP of the upstream service">
          <Input value={destIp} onChange={(e) => setDestIp(e.target.value)} placeholder="192.168.1.10" mono />
        </Field>
        <Field label="Destination port">
          <Input value={destPort} onChange={(e) => setDestPort(e.target.value)} type="number" mono />
        </Field>
        <Field label="WAF mode" hint="off = pass-through, observe = log only, block = active WAF">
          <Select value={wafMode} onChange={(e) => setWafMode(e.target.value as WafMode)}>
            <option value="off">Offline (pass-through)</option>
            <option value="observe">Observe (log only)</option>
            <option value="block">Defense (active block)</option>
          </Select>
        </Field>
      </div>
    </Dialog>
  )
}
