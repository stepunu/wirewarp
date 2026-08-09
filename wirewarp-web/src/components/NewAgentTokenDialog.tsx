import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { agents as agentsApi, settings as settingsApi } from '../lib/api'
import { Button, Dialog, Field, Select } from './ui'
import { Ic } from './icons'
import { useToast } from './Toasts'

const INSTALL_SCRIPT =
  'https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh'

export function NewAgentTokenDialog({ onClose }: { onClose: () => void }) {
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
