import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { agents as agentsApi, settings as settingsApi } from '../lib/api'
import {
  Badge,
  Button,
  Dialog,
  Field,
  FilterBar,
  K,
  Select,
  StatusDot,
  relTime,
} from '../components/ui'
import { Ic } from '../components/icons'
import { useToast } from '../components/Toasts'

const INSTALL_SCRIPT =
  'https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh'

export default function Agents() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const push = useToast()
  const [params, setParams] = useSearchParams()
  const [filter, setFilter] = useState('')
  const [type, setType] = useState('all')
  const [status, setStatus] = useState('all')
  const [showToken, setShowToken] = useState(params.get('new') === '1')
  const [focusIdx, setFocusIdx] = useState(0)
  const filterRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (showToken && params.get('new') !== '1') {
      const next = new URLSearchParams(params)
      next.set('new', '1')
      setParams(next, { replace: true })
    } else if (!showToken && params.get('new') === '1') {
      const next = new URLSearchParams(params)
      next.delete('new')
      setParams(next, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showToken])

  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list })
  const list = agentsQ.data ?? []

  const filtered = useMemo(
    () =>
      list.filter((a) => {
        if (type !== 'all' && a.type !== type) return false
        if (status !== 'all' && a.status !== status) return false
        if (filter) {
          const f = filter.toLowerCase()
          return [a.name, a.hostname, a.id, a.public_ip]
            .filter(Boolean)
            .some((x) => x!.toLowerCase().includes(f))
        }
        return true
      }),
    [list, filter, type, status],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (e.key === '/') {
        e.preventDefault()
        filterRef.current?.focus()
      }
      if (e.key === 'n' || e.key === 'N') {
        e.preventDefault()
        setShowToken(true)
      }
      if (e.key === 'j') setFocusIdx((i) => Math.min(filtered.length - 1, i + 1))
      if (e.key === 'k') setFocusIdx((i) => Math.max(0, i - 1))
      if (e.key === 'Enter' && filtered[focusIdx]) navigate(`/agents/${filtered[focusIdx].id}`)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [filtered, focusIdx, navigate])

  const delAgent = useMutation({
    mutationFn: agentsApi.del,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      push('agent removed', 'ok', 'agent://')
    },
    onError: (e) => push(e instanceof Error ? e.message : 'delete failed', 'err', 'agent://'),
  })

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="crumbs">
            <span className="scheme">wire://</span>
            <span>agents</span>
          </div>
          <h1 className="page-title">Agents</h1>
          <p className="page-sub">Go binaries running on every node. Live over WebSocket.</p>
        </div>
        <div className="page-actions">
          <Button variant="primary" leading={<Ic.plus />} onClick={() => setShowToken(true)}>
            Issue token<span className="kbd-inline">N</span>
          </Button>
        </div>
      </div>

      <FilterBar
        filterRef={filterRef}
        filter={filter}
        setFilter={setFilter}
        chips={[
          {
            label: 'type',
            value: type,
            onChange: setType,
            options: [
              ['all', 'all'],
              ['server', 'server'],
              ['client', 'client'],
            ],
          },
          {
            label: 'status',
            value: status,
            onChange: setStatus,
            options: [
              ['all', 'all'],
              ['connected', 'connected'],
              ['disconnected', 'disconnected'],
              ['pending', 'pending'],
            ],
          },
        ]}
        right={
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
            {filtered.length}/{list.length}
          </span>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th>Name</th>
              <th>Type</th>
              <th>ID</th>
              <th>Hostname</th>
              <th>Public IP</th>
              <th>Version</th>
              <th>Last seen</th>
              <th>Status</th>
              <th style={{ width: 100 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a, i) => (
              <tr
                key={a.id}
                className={focusIdx === i ? 'focused' : ''}
                onMouseEnter={() => setFocusIdx(i)}
                onClick={() => navigate(`/agents/${a.id}`)}
                style={{ cursor: 'pointer' }}
              >
                <td data-label=""><StatusDot status={a.status} label={false} /></td>
                <td data-label="name"><span className="tbl-link mono">{a.name}</span></td>
                <td data-label="type">
                  <Badge tone={a.type === 'server' ? 'info' : 'neutral'}>{a.type}</Badge>
                </td>
                <td data-label="id" className="mono" style={{ color: 'var(--fg-3)' }}>
                  {a.id.slice(0, 12)}
                </td>
                <td data-label="hostname" className="mono">{a.hostname || '—'}</td>
                <td data-label="public ip" className="mono">
                  {a.public_ip || <span style={{ color: 'var(--fg-3)' }}>—</span>}
                </td>
                <td data-label="version" className="mono">
                  {a.version || <span style={{ color: 'var(--fg-3)' }}>—</span>}
                </td>
                <td data-label="last seen" className="mono" style={{ color: 'var(--fg-2)' }}>
                  {relTime(a.last_seen)}
                </td>
                <td data-label="status"><StatusDot status={a.status} /></td>
                <td data-label="" onClick={(e) => e.stopPropagation()}>
                  <div className="row-actions">
                    <Button
                      size="sm"
                      variant="ghost"
                      style={{ color: 'var(--err)' }}
                      onClick={() => {
                        if (confirm(`Delete agent ${a.name}?`)) delAgent.mutate(a.id)
                      }}
                    >
                      remove
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="tbl-empty">
            <h3>No agents match.</h3>
            <p>Try a different filter, or issue a token to register a new agent.</p>
          </div>
        )}
      </div>

      <div style={{ marginTop: 8, fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
        <K>j</K>/<K>k</K> navigate · <K>↵</K> open · <K>/</K> filter · <K>N</K> new token
      </div>

      {showToken && <NewTokenDialog onClose={() => setShowToken(false)} />}
    </div>
  )
}

function NewTokenDialog({ onClose }: { onClose: () => void }) {
  const push = useToast()
  const [type, setType] = useState<'server' | 'client'>('client')
  const [issued, setIssued] = useState<string | null>(null)
  const settingsQ = useQuery({ queryKey: ['settings'], queryFn: settingsApi.get })

  const create = useMutation({
    mutationFn: () => agentsApi.createToken(type),
    onSuccess: (data) => setIssued(data.token),
    onError: (e) => push(e instanceof Error ? e.message : 'token failed', 'err', 'agent://'),
  })

  const publicUrl = settingsQ.data?.public_url || window.location.origin
  const internalUrl = settingsQ.data?.internal_url || publicUrl
  const controlUrl = type === 'client' ? internalUrl : publicUrl
  const installCmd = issued
    ? `curl -fsSL ${INSTALL_SCRIPT} | bash -s -- --mode ${type} --url ${controlUrl} --token ${issued}`
    : ''

  return (
    <Dialog
      title="Issue registration token"
      scheme="POST /agents/tokens"
      onClose={onClose}
      width={680}
      footer={
        issued ? (
          <>
            <span className="left">
              <span className="dot ok"></span>Token created
            </span>
            <div className="right">
              <Button onClick={onClose}>Done</Button>
            </div>
          </>
        ) : (
          <>
            <span className="left">Token authorizes a single agent to register itself.</span>
            <div className="right">
              <Button variant="ghost" onClick={onClose}>Cancel</Button>
              <Button variant="primary" onClick={() => create.mutate()} disabled={create.isPending}>
                {create.isPending ? 'issuing…' : 'Issue token'}
              </Button>
            </div>
          </>
        )
      }
    >
      {issued ? (
        <>
          <div style={{ marginBottom: 12 }}>Run this on the new node (as root, or prefix with sudo):</div>
          <pre className="code">{installCmd}</pre>
          <div className="row" style={{ marginTop: 10 }}>
            <Button
              size="sm"
              variant="ghost"
              leading={<Ic.copy />}
              onClick={() => {
                navigator.clipboard.writeText(installCmd)
                push('copied', 'ok', 'clip://')
              }}
            >
              copy
            </Button>
            <span style={{ color: 'var(--fg-3)', fontSize: 12 }}>
              token: <span className="mono">{issued}</span>
            </span>
          </div>
          {type === 'client' && (
            <div
              style={{
                marginTop: 12,
                padding: '8px 12px',
                border: '1px solid var(--info)',
                background: 'var(--info-bg)',
                color: 'var(--info)',
                borderRadius: 'var(--r-2)',
                fontSize: 12,
              }}
            >
              After the agent connects, open Tunnel Clients to assign it to a server and set gateway flags.
            </div>
          )}
        </>
      ) : (
        <div className="col" style={{ gap: 14 }}>
          <Field
            label="Agent type"
            hint="Servers run on VPSes with public IPs. Clients dial out and become reachable via a server."
          >
            <div className="row">
              <Button variant={type === 'server' ? 'primary' : 'default'} onClick={() => setType('server')}>
                tunnel server
              </Button>
              <Button variant={type === 'client' ? 'primary' : 'default'} onClick={() => setType('client')}>
                tunnel client
              </Button>
            </div>
          </Field>
          <Field label="Control URL" hint="From settings. Override there if wrong.">
            <Select value={controlUrl} disabled>
              <option>{controlUrl}</option>
            </Select>
          </Field>
        </div>
      )}
    </Dialog>
  )
}
