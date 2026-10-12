import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { siteLinks as linksApi } from '../lib/api'
import type { SiteLink, SiteLinkAccessRule, SiteLinkCreate, SiteLinkDirection, SiteLinkOptions, SiteLinkProbeRequest } from '../lib/types'
import { Badge, Button, Dialog, Field, Input, Select, Stat, relTime } from '../components/ui'
import { useRole } from '../hooks/useRole'
import { useToast } from '../components/Toasts'
import { SiteLinkRetainedGuards } from '../components/SiteLinkRetainedGuards'

const split = (value: string) => value.split(/[\s,]+/).filter(Boolean)
const directions = (direction: SiteLinkDirection): ('a_to_b' | 'b_to_a')[] => direction === 'bidirectional' ? ['a_to_b', 'b_to_a'] : [direction]
function nodeName(id: string, options?: SiteLinkOptions) { return options?.gateways.find(node => node.agent_id === id)?.name || id.slice(0, 8) }
function hubName(link: SiteLink, options?: SiteLinkOptions) { return options?.gateways.flatMap(node => node.attachments).find(attachment => attachment.hub_agent_id === link.hub_agent_id)?.hub_name || link.hub_agent_id.slice(0, 8) }
function directionName(direction: SiteLinkDirection, a: string, b: string) { return direction === 'bidirectional' ? `${a} ↔ ${b}` : direction === 'a_to_b' ? `${a} → ${b}` : `${b} → ${a}` }

export default function SiteLinks() {
  const { id } = useParams()
  return <div className="page">{id ? <SiteLinkDetail id={id} /> : <GatewaySiteLinks />}</div>
}

export function GatewaySiteLinks({ gatewayId }: { gatewayId?: string }) {
  const [creating, setCreating] = useState(false)
  const { isAdmin } = useRole()
  const links = useQuery({ queryKey: ['site-links'], queryFn: linksApi.list, refetchInterval: 5000 })
  const options = useQuery({ queryKey: ['site-link-options'], queryFn: linksApi.options })
  const rows = (links.data ?? []).filter(link => !gatewayId || link.site_a_gateway_id === gatewayId || link.site_b_gateway_id === gatewayId)
  return <>
    <div className="page-head"><div><div className="crumbs"><span className="scheme">wire://</span><span>networking</span><span className="sep">/</span><span>site links</span></div><h1 className="page-title">Site Links</h1><p className="page-sub">Connect gateway LANs through a shared WireGuard hub. The hub can inspect site traffic.</p></div>{isAdmin && <div className="page-actions"><Button variant="primary" onClick={() => setCreating(true)}>Create link</Button></div>}</div>
    <div className="card" style={{ marginBottom: 14 }}><div className="card-body">Devices that start connections must route remote subnets through their local WireWarp gateway. Destination SNAT handles replies only. LAN-device routing remains unverified.</div></div>
    {options.isError && <div role="alert" className="card-body">Could not load gateway choices: {options.error.message}</div>}
    <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Link</th><th>New connections</th><th>Hub</th><th>State</th><th>Tunnels</th><th>Configuration</th><th>LAN routes</th></tr></thead><tbody>
      {links.isError ? <tr><td colSpan={7}><div className="tbl-empty" role="alert">Could not load site links: {links.error.message}<Button size="sm" onClick={() => links.refetch()}>Retry</Button></div></td></tr> : rows.length === 0 ? <tr><td colSpan={7}><div className="tbl-empty"><h3>{links.isLoading ? 'Loading site links…' : 'No site links'}</h3><p>Create a link between two gateways attached to the same hub.</p></div></td></tr> : rows.map(link => <tr key={link.id}>
        <td data-label="Link"><Link to={`/site-links/${link.id}`}>{link.name}</Link></td>
        <td data-label="New connections">{directionName(link.direction, nodeName(link.site_a_gateway_id, options.data), nodeName(link.site_b_gateway_id, options.data))}</td>
        <td data-label="Hub">{hubName(link, options.data)}</td>
        <td data-label="State"><Badge tone={link.enabled ? 'ok' : 'neutral'}>{link.enabled ? 'Enabled' : 'Disabled'}</Badge></td>
        <td data-label="Tunnels"><Badge tone={link.agent_states.every(state => state.connected) ? 'ok' : 'warn'}>{link.agent_states.every(state => state.connected) ? 'Connected' : 'Disconnected'}</Badge></td>
        <td data-label="Configuration"><Badge tone={link.phase === 'applied' ? 'ok' : 'warn'}>{link.phase === 'applied' ? 'Applied' : 'Pending'}</Badge></td>
        <td data-label="LAN routes"><Badge tone="warn">Unverified</Badge></td>
      </tr>)}
    </tbody></table></div>
    <SiteLinkRetainedGuards />
    {creating && <SiteLinkForm options={options.data} optionsError={options.error} initialGateway={gatewayId} onClose={() => setCreating(false)} />}
  </>
}

function SiteLinkDetail({ id }: { id: string }) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const push = useToast()
  const { isAdmin } = useRole()
  const [editing, setEditing] = useState(false)
  const q = useQuery({ queryKey: ['site-link', id], queryFn: () => linksApi.get(id), refetchInterval: 5000 })
  const options = useQuery({ queryKey: ['site-link-options'], queryFn: linksApi.options })
  const toggle = useMutation({ mutationFn: () => linksApi.update(id, { enabled: !q.data?.enabled }), onSuccess: () => { qc.invalidateQueries({ queryKey: ['site-link', id] }); qc.invalidateQueries({ queryKey: ['site-links'] }) } })
  const remove = useMutation({ mutationFn: () => linksApi.del(id), onSuccess: () => { qc.invalidateQueries({ queryKey: ['site-links'] }); qc.invalidateQueries({ queryKey: ['site-link-retained-state'] }); push('Site link removed. Final deletion retains the hub deny guard. Use Restore normal forwarding to tear down retained guards before topology changes.', 'ok', 'network://'); navigate('/site-links') } })
  if (q.isLoading) return <div className="card-body">Loading site link…</div>
  if (q.isError) return <div role="alert" className="card-body">Could not load site link: {q.error.message}<Button onClick={() => q.refetch()}>Retry</Button></div>
  if (!q.data) return null
  const link = q.data
  const a = options.data?.gateways.find(node => node.agent_id === link.site_a_gateway_id)
  const b = options.data?.gateways.find(node => node.agent_id === link.site_b_gateway_id)
  const aName = a?.name || nodeName(link.site_a_gateway_id)
  const bName = b?.name || nodeName(link.site_b_gateway_id)
  return <>
    <div className="page-head"><div><div className="crumbs"><Link to="/site-links">Site Links</Link><span className="sep">/</span><span>{link.name}</span></div><h1 className="page-title">{link.name}</h1><p className="page-sub">{aName} → {hubName(link, options.data)} → {bName}</p></div>{isAdmin && <div className="page-actions"><Button onClick={() => setEditing(true)}>Edit link</Button><Button disabled={toggle.isPending} onClick={() => toggle.mutate()}>{link.enabled ? 'Disable link' : 'Enable link'}</Button><Button variant="ghost" disabled={remove.isPending} onClick={() => { if (confirm(`Delete site link ${link.name}? Its managed routes and rules will be removed. Final deletion retains the hub deny guard. Use Restore normal forwarding to tear down retained guards before topology changes.`)) remove.mutate() }}>Delete link</Button></div>}</div>
    {options.isError && <div role="alert" className="card-body">Could not load gateway choices: {options.error.message}</div>}
    {toggle.isError && <div role="alert" className="card-body">{toggle.error.message}</div>}{remove.isError && <div role="alert" className="card-body">{remove.error.message}</div>}
    <div className="server-stat-grid"><Stat label="policy" value={directionName(link.direction, aName, bName)} /><Stat label="tunnels" value={link.agent_states.every(state => state.connected) ? 'connected' : 'disconnected'} /><Stat label="configuration" value={`${link.enabled ? '' : 'disabled · '}${link.phase}`} /><Stat label="LAN routing" value="unverified" /></div>
    <div className="card" style={{ marginBottom: 14 }}><div className="card-head"><div className="title">Access and return traffic</div></div><div className="card-body col" style={{ gap: 14 }}>
      <p>Direction controls new connections. Valid established replies are allowed. Access covers only the advertised subnets below.</p>
      <p>{aName}: <span className="mono">{link.site_a_subnets.join(', ')}</span><br />{bName}: <span className="mono">{link.site_b_subnets.join(', ')}</span></p>
      {directions(link.direction).map(direction => { const snat = direction === 'a_to_b' ? link.snat_at_b : link.snat_at_a; return <div key={direction}><strong>{directionName(direction, aName, bName)}</strong><p>{snat ? 'Use destination gateway IP (SNAT). Services lose the original source IP.' : 'Preserve source IP. The destination LAN needs a return route through its gateway.'}</p><Badge tone={link.enabled && link.phase === 'applied' ? 'ok' : 'warn'}>{link.enabled && link.phase === 'applied' ? 'Return handling applied' : 'Return handling pending or disabled'}</Badge></div> })}
      {link.access_rules.length === 0 ? <p>No extra restrictions. The allowed directions can reach the selected subnets only.</p> : <><p>Only matching rules allow traffic. A direction without a matching rule is denied.</p>{link.access_rules.map((rule, i) => <p key={i}>{directionName(rule.direction, aName, bName)}: {rule.destination_cidrs.join(', ')} · {rule.protocol.toUpperCase()} · {rule.destination_ports.length ? `ports ${rule.destination_ports.join(', ')}` : 'all ports'}</p>)}</>}
    </div></div>
    <div className="card" style={{ marginBottom: 14 }}><div className="card-head"><div className="title">LAN routing prerequisites</div><Badge tone="warn">Unverified</Badge></div><div className="card-body col" style={{ gap: 12 }}><p>{link.lan_routing_prerequisite.detail}</p>{directions(link.direction).map(direction => { const source = direction === 'a_to_b' ? a : b; const destination = direction === 'a_to_b' ? link.site_b_subnets : link.site_a_subnets; return <p key={direction}>On {direction === 'a_to_b' ? aName : bName}, devices using {source?.lan_ip || 'the WireWarp gateway'} as their default gateway can enter the link. Devices using another gateway need a route for <span className="mono">{destination.join(', ')}</span> through <span className="mono">{source?.lan_ip || 'the local WireWarp gateway'}</span>.</p> })}<p>SNAT does not supply these source-device routes. WireWarp does not change LAN routers automatically.</p></div></div>
    <div className="card" style={{ marginBottom: 14 }}><div className="card-head"><div className="title">Desired and applied state</div><span className="scheme">link revision {link.revision}</span></div><div className="card-body col" style={{ gap: 14 }}>{link.agent_states.map(state => <div key={state.agent_id}><Link to={`/nodes/${state.agent_id}`}>{state.agent_id === link.hub_agent_id ? hubName(link, options.data) : nodeName(state.agent_id, options.data)}</Link> <Badge tone={state.connected && state.phase === 'applied' ? 'ok' : 'warn'}>{state.connected ? state.phase : 'disconnected'}</Badge><p>Desired revision {state.revision ?? 'unknown'} · applied {state.applied_revision ?? 'unknown'} · last report {state.last_seen ? relTime(state.last_seen) : 'never'}</p>{state.desired_hash !== state.applied_hash && <p>Desired and applied configuration differ.</p>}{state.last_error && <div role="alert" style={{ color: 'var(--err)' }}>{state.last_error}</div>}</div>)}</div></div>
    {isAdmin && <SiteLinkProbe key={`${link.direction}:${link.revision}`} link={link} aName={aName} bName={bName} />}
    {editing && <SiteLinkForm link={link} options={options.data} optionsError={options.error} onClose={() => setEditing(false)} />}
  </>
}

type DraftRule = { direction: 'a_to_b' | 'b_to_a'; cidrs: string; protocol: SiteLinkAccessRule['protocol']; ports: string }
function SiteLinkForm({ link, options, optionsError, initialGateway, onClose }: { link?: SiteLink; options?: SiteLinkOptions; optionsError: Error | null; initialGateway?: string; onClose: () => void }) {
  const qc = useQueryClient()
  const push = useToast()
  const [name, setName] = useState(link?.name || '')
  const [aId, setAId] = useState(link?.site_a_gateway_id || initialGateway || '')
  const [bId, setBId] = useState(link?.site_b_gateway_id || '')
  const [hubId, setHubId] = useState(link?.hub_agent_id || '')
  const [attachmentA, setAttachmentA] = useState(link?.site_a_attachment_id || '')
  const [attachmentB, setAttachmentB] = useState(link?.site_b_attachment_id || '')
  const gateways = options?.gateways || []
  const a = gateways.find(node => node.agent_id === aId)
  const b = gateways.find(node => node.agent_id === bId)
  const [subnetsA, setSubnetsA] = useState(link?.site_a_subnets.join(', ') || a?.advertised_subnets.join(', ') || '')
  const [subnetsB, setSubnetsB] = useState(link?.site_b_subnets.join(', ') || '')
  const [direction, setDirection] = useState<SiteLinkDirection>(link?.direction || 'a_to_b')
  const [snatA, setSnatA] = useState(link?.snat_at_a ?? true)
  const [snatB, setSnatB] = useState(link?.snat_at_b ?? true)
  const [rules, setRules] = useState<DraftRule[]>((link?.access_rules || []).map(rule => ({ direction: rule.direction, cidrs: rule.destination_cidrs.join(', '), protocol: rule.protocol, ports: rule.destination_ports.join(', ') })))
  const commonHubs = (a?.attachments || []).filter(attachment => attachment.initialized && b?.attachments.some(other => other.initialized && other.hub_agent_id === attachment.hub_agent_id)).filter((attachment, i, all) => all.findIndex(other => other.hub_agent_id === attachment.hub_agent_id) === i)
  const optionsA = (a?.attachments || []).filter(attachment => attachment.hub_agent_id === hubId && attachment.initialized)
  const optionsB = (b?.attachments || []).filter(attachment => attachment.hub_agent_id === hubId && attachment.initialized)
  const effectiveA = attachmentA || (optionsA.length === 1 ? optionsA[0].attachment_id : '')
  const effectiveB = attachmentB || (optionsB.length === 1 ? optionsB[0].attachment_id : '')
  const aName = a?.name || 'Site A'
  const bName = b?.name || 'Site B'
  const resetHub = () => { setHubId(''); setAttachmentA(''); setAttachmentB('') }
  const fitsAdvertised = (selected: string, advertised: string[]) => split(selected).every(cidr => { const range = cidrRange(cidr); return range && advertised.some(parent => { const outer = cidrRange(parent); return outer && outer[0] <= range[0] && outer[1] >= range[1] }) })
  const validation = validateForm(subnetsA, subnetsB, rules, direction) || (!link && a && b && (!fitsAdvertised(subnetsA, a.advertised_subnets) || !fitsAdvertised(subnetsB, b.advertised_subnets)) ? 'Shared subnets must belong to each gateway advertised LAN.' : null)
  const unavailable = !link && (!a?.connected || !b?.connected || !commonHubs.find(hub => hub.hub_agent_id === hubId)?.hub_connected)
  const save = useMutation({ mutationFn: async () => {
    const policy = { name: name.trim(), direction, snat_at_a: snatA, snat_at_b: snatB, access_rules: rules.map(rule => ({ direction: rule.direction, destination_cidrs: split(rule.cidrs), protocol: rule.protocol, destination_ports: split(rule.ports).map(Number) })) }
    if (link) await linksApi.update(link.id, policy)
    else { const body: SiteLinkCreate = { ...policy, site_a_gateway_id: aId, site_b_gateway_id: bId, hub_agent_id: hubId, site_a_attachment_id: effectiveA, site_b_attachment_id: effectiveB, site_a_subnets: split(subnetsA), site_b_subnets: split(subnetsB), enabled: true }; await linksApi.create(body) }
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ['site-links'] }); qc.invalidateQueries({ queryKey: ['site-link'] }); push(link ? 'site link updated' : 'site link created', 'ok', 'network://'); onClose() } })
  function updateRule(index: number, change: Partial<DraftRule>) { setRules(current => current.map((rule, i) => i === index ? { ...rule, ...change } : rule)) }
  return <Dialog title={link ? 'Edit site link' : 'Create site link'} scheme="gateway → hub → gateway" width={680} onClose={onClose} footer={<><span className="left" /><div className="right"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={save.isPending || !name.trim() || !!validation || (!link && (!aId || !bId || aId === bId || !hubId || !effectiveA || !effectiveB || unavailable))} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save link'}</Button></div></>}>
    <div className="col" style={{ gap: 14 }}>{save.isError && <div role="alert" style={{ color: 'var(--err)' }}>{save.error.message}</div>}{optionsError && <div role="alert">Could not load gateway choices: {optionsError.message}</div>}
      <Field label="Link name"><Input autoFocus value={name} maxLength={120} onChange={event => setName(event.target.value)} placeholder="Home / Vienna" /></Field>
      {link && <p>Gateway, hub, attachment, and subnet selections cannot change after creation. Create a new link to change the path.</p>}
      <div className="gridcols-2">{(['a', 'b'] as const).map(side => <Field key={side} label={`Site ${side.toUpperCase()} gateway`}><Select disabled={!!link} value={side === 'a' ? aId : bId} onChange={event => { const selected = gateways.find(node => node.agent_id === event.target.value); if (side === 'a') { setAId(event.target.value); setSubnetsA(selected?.advertised_subnets.join(', ') || '') } else { setBId(event.target.value); setSubnetsB(selected?.advertised_subnets.join(', ') || '') } resetHub() }}><option value="">Select gateway</option>{gateways.map(node => <option key={node.agent_id} value={node.agent_id} disabled={!node.connected || node.agent_id === (side === 'a' ? bId : aId)}>{node.name}{node.connected ? '' : ' (disconnected)'}</option>)}</Select></Field>)}</div>
      <Field label="Shared hub" hint="Both gateways need initialized attachments to this hub. Site traffic crosses the trusted hub."><Select disabled={!!link} value={hubId} onChange={event => { setHubId(event.target.value); setAttachmentA(''); setAttachmentB('') }}><option value="">Select common hub</option>{commonHubs.map(hub => <option key={hub.hub_agent_id} value={hub.hub_agent_id} disabled={!hub.hub_connected}>{hub.hub_name}{hub.hub_connected ? '' : ' (disconnected)'}</option>)}</Select></Field>
      {aId && bId && !commonHubs.length && <p role="alert">No shared initialized hub attachment. Connect both gateways to the same hub first.</p>}
      <div className="gridcols-2"><Field label={`${aName} attachment`}><Select disabled={!!link} value={effectiveA} onChange={event => setAttachmentA(event.target.value)}><option value="">Select attachment</option>{optionsA.map(item => <option key={item.attachment_id} value={item.attachment_id}>{item.hub_name} · {item.attachment_id.slice(0, 8)}</option>)}</Select></Field><Field label={`${bName} attachment`}><Select disabled={!!link} value={effectiveB} onChange={event => setAttachmentB(event.target.value)}><option value="">Select attachment</option>{optionsB.map(item => <option key={item.attachment_id} value={item.attachment_id}>{item.hub_name} · {item.attachment_id.slice(0, 8)}</option>)}</Select></Field></div>
      <div className="gridcols-2"><Field label={`${aName} shared subnets`} hint="IPv4 CIDRs, separated by commas."><Input disabled={!!link} value={subnetsA} onChange={event => setSubnetsA(event.target.value)} /></Field><Field label={`${bName} shared subnets`} hint="Advertise only networks this gateway serves."><Input disabled={!!link} value={subnetsB} onChange={event => setSubnetsB(event.target.value)} /></Field></div>
      <Field label="New connections" hint="One-way access permits new connections in that direction and valid replies. It blocks reverse initiation."><Select value={direction} onChange={event => setDirection(event.target.value as SiteLinkDirection)}><option value="a_to_b">{aName} → {bName}</option><option value="b_to_a">{bName} → {aName}</option><option value="bidirectional">Both directions: {aName} ↔ {bName}</option></Select></Field>
      {directions(direction).map(flow => { const atB = flow === 'a_to_b'; return <Field key={flow} label={`Return traffic at ${atB ? bName : aName}`} hint={(atB ? snatB : snatA) ? 'Destination services see this gateway IP. SNAT handles replies, not routes from initiating devices.' : 'Preserves the source IP. The destination LAN must route source subnets back through its WireWarp gateway.'}><Select value={(atB ? snatB : snatA) ? 'snat' : 'preserve'} onChange={event => (atB ? setSnatB : setSnatA)(event.target.value === 'snat')}><option value="snat">Use gateway IP (SNAT)</option><option value="preserve">Preserve source IP</option></Select></Field> })}
      <div className="card"><div className="card-head"><div className="title">Restrict access</div><Button size="sm" onClick={() => setRules(current => [...current, { direction: directions(direction)[0], cidrs: '', protocol: 'tcp', ports: '' }])}>Add restriction</Button></div><div className="card-body col" style={{ gap: 14 }}><p>{rules.length ? 'Only matching rules allow traffic. A direction without a rule is denied.' : 'No restrictions: allow selected subnets in the chosen directions. Other hub networks remain excluded.'}</p>{rules.map((rule, index) => <div key={index} className="col" style={{ gap: 10, borderTop: '1px solid var(--line)', paddingTop: 12 }}><Field label={`Rule ${index + 1} direction`}><Select value={rule.direction} onChange={event => updateRule(index, { direction: event.target.value as DraftRule['direction'] })}><option value="a_to_b" disabled={!directions(direction).includes('a_to_b')}>{aName} → {bName}</option><option value="b_to_a" disabled={!directions(direction).includes('b_to_a')}>{bName} → {aName}</option></Select></Field><Field label={`Rule ${index + 1} destination hosts`} hint="Destination IPv4 CIDRs. Use /32 for one host."><Input value={rule.cidrs} onChange={event => updateRule(index, { cidrs: event.target.value })} /></Field><div className="gridcols-2"><Field label={`Rule ${index + 1} protocol`}><Select value={rule.protocol} onChange={event => updateRule(index, { protocol: event.target.value as DraftRule['protocol'], ports: ['any', 'icmp'].includes(event.target.value) ? '' : rule.ports })}>{['tcp', 'udp', 'icmp', 'any'].map(protocol => <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>)}</Select></Field><Field label={`Rule ${index + 1} ports`} hint="Comma-separated ports. Blank permits all ports."><Input disabled={rule.protocol === 'icmp' || rule.protocol === 'any'} value={rule.ports} onChange={event => updateRule(index, { ports: event.target.value })} /></Field></div><Button size="sm" variant="ghost" onClick={() => setRules(current => current.filter((_, i) => i !== index))}>Remove rule {index + 1}</Button></div>)}</div></div>
      {validation && <div role="alert" style={{ color: 'var(--err)' }}>{validation}</div>}
      {!link && unavailable && aId && bId && hubId && <div role="alert">Both gateways and the hub must be connected before creation.</div>}
      <p>Initiating devices need a route to the remote subnets through their local gateway. Devices using another default gateway need a router or host route. SNAT does not remove this requirement.</p>
    </div>
  </Dialog>
}

function cidrRange(value: string): [number, number] | null {
  const parts = value.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/)
  if (!parts) return null
  const octets = parts.slice(1, 5).map(Number), prefix = Number(parts[5])
  if (parts.slice(1).some(part => String(Number(part)) !== part)) return null
  if (octets.some(part => part > 255) || prefix < 1 || prefix > 32) return null
  const ip = octets.reduce((total, part) => total * 256 + part, 0), size = 2 ** (32 - prefix)
  if (ip % size !== 0 || octets[0] === 127 || octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254)) return null
  return [ip, ip + size - 1]
}
function validateForm(a: string, b: string, rules: DraftRule[], direction: SiteLinkDirection): string | null {
  const networks = [...split(a), ...split(b)]
  if (!split(a).length || !split(b).length) return 'Each site needs at least one shared subnet.'
  if (split(a).length > 16 || split(b).length > 16) return 'Each site can share up to 16 subnets.'
  if (rules.length > 64) return 'Use up to 64 access restrictions.'
  const ranges = networks.map(cidrRange)
  if (ranges.some(range => !range)) return 'Use valid unicast IPv4 network CIDRs, with no host bits.'
  for (let i = 0; i < ranges.length; i++) for (let j = i + 1; j < ranges.length; j++) if (ranges[i]![0] <= ranges[j]![1] && ranges[j]![0] <= ranges[i]![1]) return 'Shared subnets must not overlap.'
  for (const rule of rules) {
    if (!directions(direction).includes(rule.direction)) return 'Remove or change rules for a direction that is no longer allowed.'
    const destinations = split(rule.cidrs).map(cidrRange)
    if (!destinations.length || destinations.some(range => !range)) return 'Each restriction needs valid destination CIDRs.'
    for (let i = 0; i < destinations.length; i++) for (let j = i + 1; j < destinations.length; j++) if (destinations[i]![0] <= destinations[j]![1] && destinations[j]![0] <= destinations[i]![1]) return 'Destination CIDRs in one restriction must not overlap.'
    const advertised = split(rule.direction === 'a_to_b' ? b : a).map(cidrRange)
    if (destinations.some(range => !advertised.some(parent => parent![0] <= range![0] && parent![1] >= range![1]))) return 'Restriction destinations must fit within the destination shared subnets.'
    if (split(rule.ports).some(port => !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) return 'Restriction ports must be whole numbers from 1 to 65535.'
    if (split(rule.ports).length > 64) return 'Use up to 64 ports in each restriction.'
  }
  return null
}

function SiteLinkProbe({ link, aName, bName }: { link: SiteLink; aName: string; bName: string }) {
  const [direction, setDirection] = useState<'a_to_b' | 'b_to_a'>(directions(link.direction)[0])
  const [ip, setIp] = useState('')
  const [port, setPort] = useState('443')
  const [command, setCommand] = useState<{ id: string; request: SiteLinkProbeRequest; at: number } | null>(null)
  const [observing, setObserving] = useState(true)
  const [elapsed, setElapsed] = useState(false)
  useEffect(() => { if (!command) return; const timer = window.setTimeout(() => { setElapsed(true); setObserving(false) }, Math.max(0, 120000 - (Date.now() - command.at))); return () => window.clearTimeout(timer) }, [command])
  const start = useMutation({ mutationFn: () => { const request = { direction, destination_ip: ip.trim(), destination_port: Number(port) }; return linksApi.test(link.id, request).then(result => ({ result, request })) }, onSuccess: ({ result, request }) => { setCommand({ id: result.command_id, request, at: Date.now() }); setElapsed(false); setObserving(true) } })
  const status = useQuery({ queryKey: ['site-link-probe', link.id, command?.id], queryFn: () => linksApi.testStatus(link.id, command!.id), enabled: !!command, refetchInterval: query => { if (query.state.data?.status !== 'pending' && query.state.data) return false; if (!command || !observing) return false; if (Date.now() - command.at > 120000) return false; return 2000 } })
  const timedOut = !!command && elapsed && (!status.data || status.data.status === 'pending')
  const inFlight = !!command && !timedOut && (!status.data || status.data.status === 'pending')
  const destinationSubnet = direction === 'a_to_b' ? link.site_b_subnets : link.site_a_subnets
  const ipRange = cidrRange(`${ip.trim()}/32`)
  const validIp = !!ipRange && destinationSubnet.some(cidr => { const range = cidrRange(cidr); return range && ipRange[0] >= range[0] && ipRange[0] <= range[1] })
  return <div className="card"><div className="card-head"><div className="title">Test connectivity</div><span className="scheme">source gateway only · TCP</span></div><div className="card-body col" style={{ gap: 14 }}><p>This probe starts on a gateway. It does not prove that LAN devices have a route into the link.</p><Field label="Probe direction"><Select value={direction} onChange={event => setDirection(event.target.value as 'a_to_b' | 'b_to_a')}>{directions(link.direction).map(flow => <option key={flow} value={flow}>{directionName(flow, aName, bName)}</option>)}</Select></Field><div className="gridcols-2"><Field label="Destination IP" hint="A service within the destination shared subnets."><Input value={ip} onChange={event => setIp(event.target.value)} /></Field><Field label="TCP port"><Input type="number" min={1} max={65535} value={port} onChange={event => setPort(event.target.value)} /></Field></div><Button disabled={!link.enabled || link.phase !== 'applied' || !validIp || !Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535 || start.isPending || inFlight} onClick={() => start.mutate()}>{start.isPending || inFlight ? 'Testing…' : 'Test connectivity'}</Button>{(!link.enabled || link.phase !== 'applied') && <p>Enable the link and wait for all three nodes to apply its configuration before testing.</p>}{start.isError && <div role="alert" style={{ color: 'var(--err)' }}>{start.error.message}</div>}{status.isError && <div role="alert">Could not load probe result: {status.error.message}</div>}{command && <div className="col" style={{ gap: 10 }}><p>Source: {command.request.direction === 'a_to_b' ? aName : bName} gateway · destination {command.request.destination_ip}:{command.request.destination_port} · TCP · {new Date(command.at).toLocaleString()}</p><Badge tone={status.data?.status === 'success' ? 'ok' : 'warn'}>{status.data?.status || 'pending'}</Badge>{status.data?.result && <p>{status.data.result.connected ? 'Gateway reached the service.' : 'Gateway could not reach the service.'} {status.data.result.error || ''} ({status.data.result.duration_ms} ms)</p>}{timedOut && <p>Observation timed out. The remote probe may still report a result. Refresh to check again.</p>}<Button size="sm" onClick={() => { setObserving(false); status.refetch() }}>Refresh result</Button><p>LAN-device routing: Unverified.</p></div>}</div></div>
}
