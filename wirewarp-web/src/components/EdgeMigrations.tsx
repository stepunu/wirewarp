import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { edgeMigrations as migrationsApi, nodes as nodesApi, tunnelClientAttachments as attachmentsApi } from '../lib/api'
import type { EdgeMigration, EdgeMigrationPreview, EdgeMigrationRequest, EdgeRoute, Node } from '../lib/types'
import { Badge, Button, Dialog, Field, KV, Select } from './ui'
import { useRole } from '../hooks/useRole'

function migrationError(error: Error): string {
  const body = error.message.replace(/^\d+:\s*/, '')
  try {
    const parsed: unknown = JSON.parse(body)
    if (parsed && typeof parsed === 'object' && 'detail' in parsed && typeof parsed.detail === 'string') return parsed.detail
  } catch { /* Non-JSON network errors retain their original message. */ }
  return error.message
}

const phaseLabel: Record<EdgeMigration['phase'], string> = {
  staged: 'Staged · source remains active',
  provisioning: 'Provisioning · source remains active',
  switched: 'Cutover sent · waiting for both nodes',
  completed: 'Cutover verified on both nodes',
  rollback_pending: 'Rollback sent · waiting for both nodes',
  rolled_back: 'Rollback verified on both nodes',
  cancel_pending: 'Cancel sent · waiting for gateway cleanup',
  canceled: 'Staging canceled · source remains active',
}

export function EdgeMigrationPanel({ nodeId }: { nodeId: string }) {
  const { isAdmin } = useRole()
  const qc = useQueryClient()
  const [selected, setSelected] = useState('')
  const records = useQuery({ queryKey: ['edge-migrations'], queryFn: migrationsApi.list, refetchInterval: 5000 })
  const rows = (records.data ?? []).filter(record => record.source_agent_id === nodeId || record.target_agent_id === nodeId)
  const migration = rows.find(record => record.id === selected)
  const action = useMutation({
    mutationFn: ({ record, name }: { record: EdgeMigration; name: 'provision' | 'test' | 'finalize' | 'rollback' | 'cancel' }) => migrationsApi.action(record.id, name, record.revision),
    onSuccess: result => {
      qc.setQueryData<EdgeMigration[]>(['edge-migrations'], previous => previous?.map(record => record.id === result.id ? result : record))
      qc.invalidateQueries({ queryKey: ['edge-migrations'] })
      qc.invalidateQueries({ queryKey: ['edge-routes'] })
      qc.invalidateQueries({ queryKey: ['node-edge'] })
    },
    onError: () => { qc.invalidateQueries({ queryKey: ['edge-migrations'] }) },
  })
  const discard = useMutation({
    mutationFn: (record: EdgeMigration) => migrationsApi.discard(record.id, record.revision),
    onSuccess: () => { setSelected(''); qc.invalidateQueries({ queryKey: ['edge-migrations'] }) },
    onError: () => { qc.invalidateQueries({ queryKey: ['edge-migrations'] }) },
  })
  return <div className="card" style={{ marginTop: 14 }}>
    <div className="card-head"><div><div className="title">Edge migrations</div><div className="scheme">Move a VPS route to a gateway with a staged cutover</div></div><Button size="sm" variant="ghost" onClick={() => records.refetch()}>Refresh</Button></div>
    <div className="card-body">
      <p>The source route remains active during staging and gateway tests. Cutover moves the route and keeps the VPS as its encrypted relay.</p>
      <p style={{ marginTop: 8 }}>Private ACME stores are not copied. Existing VPS services are not removed. Configure LAN DNS separately.</p>
      {records.isError && <div role="alert">Could not load migrations: {migrationError(records.error)}<Button size="sm" onClick={() => records.refetch()}>Retry</Button></div>}
      {!records.isError && !rows.length && <div className="tbl-empty"><h3>{records.isLoading ? 'Loading migrations…' : 'No migrations'}</h3><p>Use “Migrate to gateway” on an active VPS public route.</p></div>}
      {rows.length > 0 && <div className="col" style={{ gap: 10, marginTop: 14 }}>{rows.map(record => <div key={record.id} className="row" style={{ flexWrap: 'wrap', justifyContent: 'space-between', gap: 8 }}>
        <div><div className="mono">{record.domain || record.source_route_id}</div><div className="scheme">{phaseLabel[record.phase]} · revision {record.revision}</div></div>
        <Button size="sm" variant={selected === record.id ? 'primary' : 'ghost'} onClick={() => { setSelected(record.id); action.reset(); discard.reset() }}>Review migration</Button>
      </div>)}</div>}
      {migration && <div className="col" style={{ gap: 14, marginTop: 20 }}>
        <ol style={{ margin: 0, paddingLeft: 20 }}>
          <li>Stage a disabled gateway copy. The source continues to serve requests.</li>
          <li>Provision the gateway listener and wait for its exact configuration acknowledgement.</li>
          <li>Test the staged TLS, origin, and route response from the gateway.</li>
          <li>Cut over public ingress. Wait for both nodes to acknowledge the new configuration.</li>
        </ol>
        <KV pairs={[
          ['Source', <Link to={`/nodes/${migration.source_agent_id}`}>{migration.source_agent_id.slice(0, 8)}</Link>],
          ['Gateway', <Link to={`/nodes/${migration.target_agent_id}`}>{migration.target_agent_id.slice(0, 8)}</Link>],
          ['Visibility', migration.visibility === 'both' ? 'LAN and public' : 'Public through VPS relay'],
          ['Phase', phaseLabel[migration.phase]],
          ['Revision', String(migration.revision)],
          ['Desired gateway version', migration.stage_version_id || 'Not provisioned'],
          ['Desired configuration hash', <span style={{ overflowWrap: 'anywhere' }}>{migration.stage_desired_hash || 'Not provisioned'}</span>],
          ['Gateway applied acknowledgement', migration.stage_applied ? <Badge tone="ok">Exact version applied</Badge> : <Badge tone="warn">Unverified</Badge>],
          ['Gateway TLS / origin / route probe', <Badge tone={migration.probe_status === 'verified' ? 'ok' : 'warn'}>{migration.probe_status || 'not_run'}</Badge>],
          ['Public cutover readiness', migration.ready_to_switch ? <Badge tone="ok">Ready</Badge> : <Badge tone="warn">Not ready</Badge>],
          ['Both nodes applied after cutover / rollback', migration.runtime_verified ? <Badge tone="ok">Verified</Badge> : <Badge tone="warn">Unverified</Badge>],
        ]} />
        {migration.readiness_detail && <div role="status">{migration.readiness_detail}</div>}
        {migration.last_error && <div role="alert">{migration.last_error}</div>}
        {action.isError && <div role="alert" style={{ overflowWrap: 'anywhere' }}>Migration action failed: {migrationError(action.error)}. The record remains available for review.</div>}
        {discard.isError && <div role="alert" style={{ overflowWrap: 'anywhere' }}>Could not discard migration history: {migrationError(discard.error)}</div>}
        <div className="scheme">LAN-client routing and DNS remain unverified. A gateway probe does not prove reachability from LAN devices.</div>
        {isAdmin && <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          {['staged', 'provisioning'].includes(migration.phase) && <Button disabled={action.isPending} onClick={() => action.mutate({ record: migration, name: 'provision' })}>{migration.phase === 'staged' ? 'Provision gateway' : 'Reprovision gateway'}</Button>}
          {migration.phase === 'provisioning' && <Button disabled={action.isPending || !migration.stage_applied} onClick={() => action.mutate({ record: migration, name: 'test' })}>Test staged route</Button>}
          {migration.phase === 'provisioning' && <Button variant="primary" disabled={action.isPending || !migration.ready_to_switch} onClick={() => action.mutate({ record: migration, name: 'finalize' })}>Cut over public route</Button>}
          {['switched', 'completed'].includes(migration.phase) && <Button variant="danger" disabled={action.isPending} onClick={() => action.mutate({ record: migration, name: 'rollback' })}>Roll back to VPS</Button>}
          {['staged', 'provisioning'].includes(migration.phase) && <Button variant="danger" disabled={action.isPending} onClick={() => action.mutate({ record: migration, name: 'cancel' })}>Cancel staging</Button>}
          {['canceled', 'rolled_back', 'completed'].includes(migration.phase) && <Button variant="danger" disabled={action.isPending || discard.isPending || migration.phase === 'completed' && !migration.runtime_verified} onClick={() => { if (confirm('Discard this migration history? The source route remains. This removes the saved rollback record.')) discard.mutate(migration) }}>Discard migration history</Button>}
          {action.isPending && <span role="status">Sending migration action…</span>}
        </div>}
        <details><summary>Preserved effective policy and prerequisites</summary><ul>{migration.prerequisites.map(item => <li key={item}>{item}</li>)}</ul><pre className="code" style={{ maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(migration.effective_policy, null, 2)}</pre></details>
      </div>}
    </div>
  </div>
}

export function EdgeMigrationDialog({ source, route, onClose }: { source: Node; route: EdgeRoute; onClose: () => void }) {
  const qc = useQueryClient()
  const [gatewayId, setGatewayId] = useState('')
  const [attachmentId, setAttachmentId] = useState('')
  const [visibility, setVisibility] = useState<'public_only' | 'both'>('both')
  const [preview, setPreview] = useState<EdgeMigrationPreview | null>(null)
  const nodes = useQuery({ queryKey: ['nodes'], queryFn: nodesApi.list })
  const gateway = nodes.data?.find(node => node.agent_id === gatewayId)
  const attachments = useQuery({ queryKey: ['migration-attachments', gateway?.tunnel_client_id], queryFn: () => attachmentsApi.list({ tunnel_client_id: gateway!.tunnel_client_id! }), enabled: !!gateway?.tunnel_client_id })
  const readyAttachments = (attachments.data ?? []).filter(item => item.tunnel_server_id === source.tunnel_server_id && item.wg_public_key)
  const selectedAttachment = attachmentId || readyAttachments[0]?.id || ''
  const body: EdgeMigrationRequest = { source_route_id: route.id, target_agent_id: gatewayId, target_attachment_id: selectedAttachment, visibility }
  const stage = useMutation({ mutationFn: migrationsApi.stage, onSuccess: () => { qc.invalidateQueries({ queryKey: ['edge-migrations'] }); onClose() }, onError: () => setPreview(null) })
  const getPreview = useMutation({
    mutationFn: migrationsApi.preview,
    onSuccess: (result, sent) => { if (JSON.stringify(sent) === JSON.stringify(body)) { setPreview(result); stage.reset() } },
  })
  return <Dialog title="Migrate to gateway" scheme="Preview → stage → provision → test → cut over" width={760} onClose={onClose} footer={<><span className="left">{route.domain}</span><div className="right"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={!gatewayId || !selectedAttachment || getPreview.isPending || stage.isPending} onClick={() => getPreview.mutate(body)}>{getPreview.isPending ? 'Previewing…' : 'Preview'}</Button><Button variant={preview ? "primary" : "default"} disabled={!preview || stage.isPending} onClick={() => { if (preview) stage.mutate({ ...body, expected_source_fingerprint: preview.source_fingerprint }) }}>{stage.isPending ? 'Staging…' : 'Stage migration'}</Button></div></>}>
    <div className="col" style={{ gap: 14 }}>
      <p>Staging creates a disabled gateway copy. The VPS source stays active until you explicitly cut over after successful gateway tests.</p>
      <Field label="Target gateway" hint="Enable Security Edge and configure its LAN and selected tunnel listeners first."><Select value={gatewayId} onChange={event => { setGatewayId(event.target.value); setAttachmentId(''); setPreview(null); getPreview.reset(); stage.reset() }}><option value="">{nodes.isLoading ? 'Loading gateways…' : 'Select gateway'}</option>{(nodes.data ?? []).filter(node => node.role === 'gateway').map(node => <option key={node.agent_id} value={node.agent_id}>{node.name} · {node.status}</option>)}</Select></Field>
      {nodes.isError && <div role="alert">Could not load gateways: {migrationError(nodes.error)}<Button size="sm" onClick={() => nodes.refetch()}>Retry</Button></div>}
      <Field label="Relay attachment" hint="The initialized attachment must connect the target gateway to this source VPS."><Select value={selectedAttachment} onChange={event => { setAttachmentId(event.target.value); setPreview(null) }} disabled={!gatewayId || attachments.isLoading}><option value="">{attachments.isLoading ? 'Loading attachments…' : 'Select initialized attachment'}</option>{readyAttachments.map(item => <option key={item.id} value={item.id}>{item.wg_interface} · {item.tunnel_ip}</option>)}</Select></Field>
      {gatewayId && !attachments.isLoading && !attachments.isError && !readyAttachments.length && <div role="status">This gateway has no initialized attachment to the source VPS.</div>}
      {attachments.isError && <div role="alert">Could not load attachments: {migrationError(attachments.error)}<Button size="sm" onClick={() => attachments.refetch()}>Retry</Button></div>}
      <Field label="Target visibility" hint="TLS, WAF, cache, and client identity run on the gateway. Public HTTPS crosses the VPS relay."><Select value={visibility} onChange={event => { setVisibility(event.target.value as typeof visibility); setPreview(null) }}><option value="both">LAN and public</option><option value="public_only">Public through VPS relay</option></Select></Field>
      {getPreview.isError && <div role="alert" style={{ overflowWrap: 'anywhere' }}>Preview conflict or prerequisite: {migrationError(getPreview.error)}</div>}
      {stage.isError && <div role="alert" style={{ overflowWrap: 'anywhere' }}>Staging failed: {migrationError(stage.error)}. Review the source and preview again.</div>}
      {preview && <div className="col" style={{ gap: 12 }}>
        <KV pairs={[
          ['Route', preview.domain], ['Origin', `${preview.destination_ip}:${preview.destination_port}`],
          ['Target visibility', preview.visibility === 'both' ? 'LAN and public' : 'Public through VPS relay'],
          ['Public ingress', 'The existing VPS becomes an encrypted HTTPS relay at cutover'],
          ['Security processing', 'Traefik, TLS, WAF, and cache move to the gateway'],
          ['Gateway public listener', `${preview.planned_changes.public_bind_ip.before || 'Unset'} → ${preview.planned_changes.public_bind_ip.after}`],
          ['Public DNS', 'Keep the existing VPS DNS target for public HTTPS'],
          ['LAN DNS', preview.visibility === 'both' ? `Point the hostname to ${gateway?.lan_bind_ip || 'the configured gateway LAN listener'}` : 'This route has no LAN listener'],
        ]} />
        {preview.planned_changes.public_bind_ip.assigned_on_provision && <p>The public tunnel listener is assigned during provisioning. Staging does not change the gateway listener.</p>}
        <ul style={{ margin: 0, paddingLeft: 20 }}>{Object.entries(preview.preservation).map(([key, value]) => <li key={key}><strong>{key.replace(/_/g, ' ')}:</strong> {String(value)}</li>)}</ul>
        <p>Private ACME stores are not transferred. Configure and test gateway certificates before cutover. Existing VPS services remain installed.</p>
        <details><summary>Full preserved policy</summary><pre className="code" style={{ maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(preview.effective_policy, null, 2)}</pre></details>
      </div>}
    </div>
  </Dialog>
}
