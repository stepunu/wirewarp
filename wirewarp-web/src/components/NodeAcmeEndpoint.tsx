import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { nodes as nodesApi } from '../lib/api'
import type { NodeEdgeCapabilities } from '../lib/types'
import { Button, Field, Input } from './ui'
import { useRole } from '../hooks/useRole'
import { useToast } from './Toasts'

function errorDetail(error: Error): string {
  try {
    const data: unknown = JSON.parse(error.message.replace(/^\d+:\s*/, ''))
    if (data && typeof data === 'object' && 'detail' in data && typeof data.detail === 'string') return data.detail
    if (data && typeof data === 'object' && 'detail' in data && Array.isArray(data.detail)) {
      const messages = data.detail.flatMap(item => item && typeof item === 'object' && 'msg' in item && typeof item.msg === 'string' ? [item.msg] : [])
      if (messages.length) return messages.join('; ')
    }
  } catch { /* Network errors are plain text. */ }
  return error.message
}

export function NodeAcmeEndpoint({ agentId }: { agentId: string }) {
  const capabilities = useQuery({ queryKey: ['edge-capabilities', agentId], queryFn: () => nodesApi.edgeCapabilities(agentId) })
  return <div className="card">
    <div className="card-head"><div className="title">Knot / RFC2136 update endpoint</div></div>
    <div className="card-body">
      {capabilities.isPending ? <p>Loading node update endpoint…</p> : capabilities.isError ? <div role="alert">Could not load node update endpoint: {errorDetail(capabilities.error)}<Button size="sm" onClick={() => capabilities.refetch()}>Retry endpoint</Button></div> : <EndpointEditor key={`${agentId}:${capabilities.data.rfc2136_nameserver_override ?? ''}`} agentId={agentId} capabilities={capabilities.data} />}
    </div>
  </div>
}

function EndpointEditor({ agentId, capabilities }: { agentId: string; capabilities: NodeEdgeCapabilities }) {
  const { isAdmin } = useRole()
  const push = useToast()
  const qc = useQueryClient()
  const saved = capabilities.rfc2136_nameserver_override ?? ''
  const [endpoint, setEndpoint] = useState(saved)
  const save = useMutation({
    mutationFn: (value: string | null) => nodesApi.updateEdgeCapabilities(agentId, { rfc2136_nameserver_override: value }),
    onSuccess: data => {
      setEndpoint(data.rfc2136_nameserver_override ?? '')
      qc.setQueryData(['edge-capabilities', agentId], data)
      qc.invalidateQueries({ queryKey: ['node-edge', agentId] })
      push('node update endpoint saved', 'ok', 'tls://')
    },
  })
  const unsaved = endpoint.trim() !== saved
  return <div className="col" style={{ gap: 12 }}>
    <p>Effective update endpoint: <strong className="mono" style={{ overflowWrap: 'anywhere' }}>{capabilities.rfc2136_effective_nameserver || 'Not configured'}</strong> · {saved ? 'node override' : 'inherited global setting'}</p>
    <p>When Knot / RFC2136 is selected, this node sends signed TXT updates to this writable DNS primary. Certificate issuance and the selected-node DNS test use the same endpoint.</p>
    <p>The TSIG key and secret remain in global ACME settings. DNS propagation resolvers are separate and stay unchanged.</p>
    <Field label="Node update endpoint override" hint="Leave blank to inherit the global endpoint. Use a hostname, IPv4, or [IPv6]:port. The default port is 53.">
      <Input mono value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder="10.50.30.53:53" disabled={!isAdmin || save.isPending} />
    </Field>
    {unsaved && <p role="status">Node endpoint changes are not saved yet.</p>}
    {save.isError && <div role="alert">Could not save node endpoint: {errorDetail(save.error)}</div>}
    {isAdmin && <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Button disabled={!unsaved || save.isPending} onClick={() => save.mutate(endpoint.trim() || null)}>{save.isPending ? 'Saving…' : 'Save node endpoint'}</Button>
      <Button variant="ghost" disabled={!saved || save.isPending} onClick={() => save.mutate(null)}>Clear override</Button>
    </div>}
  </div>
}
