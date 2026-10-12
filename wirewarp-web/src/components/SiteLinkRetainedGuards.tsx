import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { siteLinks as linksApi } from '../lib/api'
import type { SiteLinkRetainedStates } from '../lib/types'
import { Badge, Button, Dialog, Field, Input } from './ui'
import { useRole } from '../hooks/useRole'

function errorDetail(error: Error): string {
  try {
    const body: unknown = JSON.parse(error.message.replace(/^\d+:\s*/, ''))
    if (body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string') return body.detail
  } catch { /* Network errors are plain text. */ }
  return error.message
}

export function SiteLinkRetainedGuards() {
  const { isAdmin } = useRole()
  const qc = useQueryClient()
  const [reviewed, setReviewed] = useState<SiteLinkRetainedStates | null>(null)
  const [confirmation, setConfirmation] = useState('')
  const [requested, setRequested] = useState(false)
  const state = useQuery({ queryKey: ['site-link-retained-state'], queryFn: linksApi.retainedState, refetchInterval: 3000 })
  const teardown = useMutation({
    mutationFn: linksApi.teardown,
    onSuccess: () => { setRequested(true); setReviewed(null); setConfirmation(''); qc.invalidateQueries({ queryKey: ['site-link-retained-state'] }); qc.invalidateQueries({ queryKey: ['site-links'] }) },
    onError: () => { qc.invalidateQueries({ queryKey: ['site-link-retained-state'] }) },
  })
  const beginReview = () => { if (state.data) { setReviewed(state.data); teardown.reset() } }
  return <div className="card" style={{ marginTop: 14 }}>
    <div className="card-head"><div className="title">Retained Site Links guards</div><Button size="sm" onClick={() => state.refetch()}>Refresh guards</Button></div>
    <div className="card-body col" style={{ gap: 12 }}>
      {state.isLoading ? <p>Loading retained guards…</p> : state.isError ? <div role="alert">Could not load retained guards: {errorDetail(state.error)}<Button size="sm" onClick={() => state.refetch()}>Retry guards</Button></div> : state.data && <>
        {!state.data.states.length ? <p>{requested ? 'Normal forwarding restored. All nodes acknowledged cleanup and released Site Links ownership.' : 'No retained Site Links state.'}</p> : <>
          <p>Deleting the last link retains Site Links isolation. Restore normal forwarding explicitly to remove these guards and release node ownership.</p>
          {state.data.states.map(node => <div key={node.agent_id} style={{ overflowWrap: 'anywhere' }}>
            <Link to={`/nodes/${node.agent_id}`}>{node.name}</Link> · {node.node_role} <Badge tone={node.connected ? 'neutral' : 'warn'}>{node.connected ? 'Connected' : 'Disconnected'}</Badge> <Badge tone={node.phase === 'applied' ? 'ok' : 'warn'}>{node.phase}</Badge>
            <p>Revision {node.revision} · configuration {node.desired_hash}</p>
            {node.last_error && <div role="alert" style={{ color: 'var(--err)' }}>{node.last_error}</div>}
          </div>)}
          <p>Ownership remains until every node acknowledges cleanup. A disconnected node or a pending command has not completed teardown.</p>
          {state.data.has_links ? <p>Delete every link, including disabled links, before restoring normal forwarding.</p> : !state.data.can_teardown && <p>Wait for the empty Site Links configuration to apply on all nodes before teardown.</p>}
          {isAdmin && <Button disabled={!state.data.can_teardown || state.data.has_links || teardown.isPending} onClick={beginReview}>Restore normal forwarding</Button>}
        </>}
      </>}
    </div>
    {reviewed && <Dialog title="Restore normal forwarding" onClose={() => { if (!teardown.isPending) setReviewed(null) }} footer={<><div className="left"><Button variant="ghost" disabled={teardown.isPending} onClick={() => setReviewed(null)}>Cancel</Button></div><div className="right"><Button variant={confirmation === 'Restore normal forwarding' ? 'danger' : 'default'} disabled={confirmation !== 'Restore normal forwarding' || !reviewed.can_teardown || reviewed.has_links || teardown.isPending} onClick={() => teardown.mutate({ confirm_restore_normal_forwarding: true, expected_states: reviewed.states.map(({ agent_id, revision, desired_hash }) => ({ agent_id, revision, desired_hash })) })}>{teardown.isPending ? 'Requesting…' : 'Confirm restoration'}</Button></div></>}>
      <div className="col" style={{ gap: 14 }}>
        <p>Removing these guards ends Site Links isolation and restores normal hub forwarding. Ordinary WireWarp forwarding rules remain. Review every node before confirming.</p>
        {reviewed.states.map(node => <div key={node.agent_id} style={{ overflowWrap: 'anywhere' }}>{node.name} · revision {node.revision} · {node.phase}<p>{node.desired_hash}</p></div>)}
        <Field label="Confirmation" hint="Type Restore normal forwarding to confirm."><Input value={confirmation} onChange={event => setConfirmation(event.target.value)} /></Field>
        {teardown.isError && <div role="alert">Restoration failed: {errorDetail(teardown.error)}. Review current state before retrying.</div>}
        <Button disabled={teardown.isPending || !state.data} onClick={beginReview}>Review current state</Button>
        <p>The request starts cleanup. Completion requires an acknowledgement from every node.</p>
      </div>
    </Dialog>}
  </div>
}
