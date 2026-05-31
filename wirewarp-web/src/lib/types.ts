export type Role = 'admin' | 'operator' | 'viewer' | 'vpn_user'
export type AuthProvider = 'local' | 'oidc' | 'ldap'

export interface User {
  id: string
  username: string
  email: string
  role: Role
  is_active: boolean
  auth_provider: AuthProvider
  last_login_at: string | null
  vpn_enabled: boolean
  created_at: string
}

export interface Agent {
  id: string
  name: string
  type: 'server' | 'client'
  hostname: string | null
  public_ip: string | null
  status: 'connected' | 'disconnected' | 'pending'
  version: string | null
  last_seen: string | null
  created_at: string
}

export interface RegistrationToken {
  id: string
  agent_type: string
  used: boolean
  expires_at: string
  created_at: string
}

export interface RegistrationTokenIssued extends RegistrationToken {
  /** Plaintext, returned exactly once on issuance. Server keeps only its SHA-256 hash. */
  token: string
}

export interface TunnelServerIP {
  id: string
  tunnel_server_id: string
  address: string
  label: string | null
  is_primary: boolean
  port_forward_count: number
  created_at: string
}

export interface TunnelServer {
  id: string
  agent_id: string
  wg_port: number
  wg_interface: string
  primary_ip: string | null
  public_iface: string
  wg_public_key: string | null
  tunnel_network: string
  created_at: string
  ips: TunnelServerIP[]
}

export interface TunnelClientAttachment {
  id: string
  tunnel_client_id: string
  tunnel_server_id: string
  tunnel_ip: string
  wg_interface: string
  wg_public_key: string | null
  fwmark: number
  route_table_id: number
  created_at: string
}

export interface TunnelClient {
  id: string
  agent_id: string
  vm_network: string | null
  lan_ip: string | null
  is_gateway: boolean
  status: string
  created_at: string
  attachments: TunnelClientAttachment[]
}

export interface DnsRecordRef {
  provider: string
  zone_id: string
  record_id: string
  name: string
}

export interface LanClient {
  id: string
  tunnel_client_id: string
  lan_ip: string
  mac: string | null
  hostname: string | null
  last_seen: string
  bytes_recent: number
  egress_attachment_id: string | null
  egress_tunnel_server_ip_id: string | null
  dns_record_ids: DnsRecordRef[] | null
  created_at: string
}

export interface WgPeerSnapshot {
  id: number
  agent_id: string
  interface: string
  kind: 'mesh' | 'vpn'
  public_key: string
  endpoint: string | null
  allowed_ips: string | null
  last_handshake_unix: number | null
  rx_bytes: number
  tx_bytes: number
  persistent_keepalive: number | null
  updated_at: string
  handshake_age_seconds: number | null
}

export interface TunnelServerSummary extends TunnelServer {
  peer_count: number
  total_rx_bytes: number
  total_tx_bytes: number
  recent_heal_count: number
  forward_count: number
}

export interface TunnelClientAttachmentHealth {
  attachment_id: string
  wg_interface: string
  peer_count: number
  last_handshake_unix: number | null
}

export interface TunnelClientSummary extends TunnelClient {
  total_rx_bytes: number
  total_tx_bytes: number
  recent_heal_count: number
  attachment_health: TunnelClientAttachmentHealth[]
}

export interface CrowdSecScenario {
  name: string
  count: number
}

export interface CrowdSecTopIp {
  ip: string
  count: number
}

export interface CrowdSecStatus {
  installed: boolean
  running: boolean
  version: string | null
  total_decisions: number
  top_scenarios: CrowdSecScenario[]
  top_ips: CrowdSecTopIp[]
  error: string | null
  phase: 'healthy' | 'degraded' | 'pending' | 'unknown'
  last_error: string | null
  appsec_enabled: boolean
  bouncer_registered: boolean
  updated_at: string | null
}

export interface HealEvent {
  id: number
  agent_id: string
  mode: 'server' | 'client'
  interface: string | null
  healed: string[]
  occurred_at: string
}

export interface SensitiveServiceTip {
  key: string
  label: string
  severity: 'high' | 'medium'
  message: string
}

export interface PortForward {
  id: string
  attachment_id: string
  tunnel_server_ip_id: string | null
  protocol: 'tcp' | 'udp'
  public_port: number
  public_port_end: number | null
  destination_ip: string
  destination_port: number
  destination_port_end: number | null
  description: string | null
  active: boolean
  service_kind: ServiceKind
  domain: string | null
  created_at: string
  sensitive_service: SensitiveServiceTip | null
}

export interface ServiceTemplate {
  id: string
  name: string
  protocol: string
  ports: string
  is_builtin: boolean
  created_at: string
}

export interface OidcConfig {
  issuer?: string
  client_id?: string
  client_secret?: string
  redirect_url?: string
  scopes?: string[]
  username_claim?: string
  email_claim?: string
  role_claim?: string
  claim_role_map?: Record<string, Role>
  default_role?: Role
  vpn_group?: string
}

export interface LdapConfig {
  url?: string
  user_dn_template?: string
  bind_dn?: string
  bind_password?: string
  group_search_base?: string
  group_member_attr?: string
  group_filter_template?: string
  group_role_map?: Record<string, Role>
  default_role?: Role
  vpn_group?: string
}

export interface SystemSettings {
  public_url: string | null
  internal_url: string | null
  instance_name: string
  agent_token_expiry_hours: number
  dns_provider: string | null
  cloudflare_token_set: boolean
  auth_provider: AuthProvider
  oidc_config: Omit<OidcConfig, 'client_secret'> | null
  ldap_config: Omit<LdapConfig, 'bind_password'> | null
  oidc_secret_set: boolean
  ldap_secret_set: boolean
  captcha_provider: string | null
  captcha_site_key: string | null
  captcha_site_key_set: boolean
  captcha_secret_key_set: boolean
  letsencrypt_enabled: boolean
  letsencrypt_email: string | null
  letsencrypt_challenge: 'dns-01' | 'tls-alpn-01' | 'http-01'
  letsencrypt_dns_provider: string | null
  letsencrypt_dns_resolvers: string[]
  letsencrypt_use_staging: boolean
  letsencrypt_cloudflare_token_set: boolean
}

export interface SystemSettingsUpdate {
  public_url?: string | null
  internal_url?: string | null
  instance_name?: string | null
  agent_token_expiry_hours?: number | null
  dns_provider?: string | null
  cloudflare_api_token?: string | null
  auth_provider?: AuthProvider
  oidc_config?: OidcConfig | null
  ldap_config?: LdapConfig | null
  captcha_provider?: string | null
  captcha_site_key?: string | null
  captcha_secret_key?: string | null
  letsencrypt_enabled?: boolean | null
  letsencrypt_email?: string | null
  letsencrypt_challenge?: 'dns-01' | 'tls-alpn-01' | 'http-01' | null
  letsencrypt_dns_provider?: string | null
  letsencrypt_dns_resolvers?: string[] | null
  letsencrypt_use_staging?: boolean | null
  letsencrypt_cloudflare_api_token?: string | null
}

export type NodeRole = 'server' | 'gateway' | 'client'
export type EdgeMode = 'tcp_udp_only' | 'security_edge'
export type EdgeState = 'enabled' | 'disabled'
export type EdgeInstallPhase = 'disabled' | 'pending' | 'healthy' | 'degraded' | 'unknown'

export interface EdgeComponent {
  component: string
  desired: 'enabled' | 'disabled' | string
  installed: boolean
  running: boolean
  phase: 'healthy' | 'degraded' | 'pending' | 'disabled' | 'unknown' | string
  version: string | null
  last_error: string | null
  updated_at: string | null
}

export interface Node {
  agent_id: string
  name: string
  role: NodeRole
  status: 'connected' | 'disconnected' | 'pending'
  hostname: string | null
  public_ip: string | null
  version: string | null
  last_seen: string | null
  tunnel_server_id: string | null
  tunnel_client_id: string | null
  is_gateway: boolean
  edge_phase: 'healthy' | 'degraded' | 'pending' | 'disabled' | 'unknown' | null
  edge_mode: EdgeMode | null
  edge_state: EdgeState | null
  edge_install_phase: EdgeInstallPhase | null
  edge_components: Record<string, EdgeComponent>
}

export type VpnProtocol = 'tcp' | 'udp' | 'icmp' | 'any'
export type VpnTunnelMode = 'split' | 'full'

export interface VpnEndpoint {
  id: string
  tunnel_client_id: string
  wg_interface: string
  listen_port: number
  vpn_network: string
  public_endpoint: string
  wg_public_key: string | null
  dns_servers: string[] | null
  enabled: boolean
  created_at: string
}

export interface VpnPermission {
  id: string
  user_id: string
  vpn_endpoint_id: string
  destination: string
  protocol: VpnProtocol
  port_range_start: number | null
  port_range_end: number | null
}

export interface VpnUserPermissions {
  user_id: string
  username: string
  auth_provider: string
  profile_count: number
  permissions: VpnPermission[]
}

export interface VpnPermissionInput {
  destination: string
  protocol: VpnProtocol
  port_range_start?: number | null
  port_range_end?: number | null
}

export interface VpnProfile {
  id: string
  user_id: string
  vpn_endpoint_id: string
  label: string
  tunnel_ip: string
  wg_public_key: string
  tunnel_mode: VpnTunnelMode
  last_handshake_at: string | null
  created_at: string
}

export interface VpnProfileIssued extends VpnProfile {
  /** Rendered `.conf` text returned ONCE on create / regenerate. */
  config_text: string
  /** Plaintext WireGuard private key, server-generated, never persisted. */
  wg_private_key: string
  /** The (user, endpoint) permission set the profile inherited at create time. */
  permissions: VpnPermission[]
}

export interface AuditEntry {
  id: string
  agent_id: string | null
  agent_name: string | null
  actor_user_id: string | null
  actor_username: string | null
  command_type: string
  event_type: string | null
  success: boolean | null
  output: string | null
  details_json: Record<string, unknown> | null
  executed_at: string
}

// ──────────────────────────────────────────────
// Security Edge Console (Phase 12)
// ──────────────────────────────────────────────

export type WafMode = 'off' | 'observe' | 'block'
export type AuthMode = 'none' | 'basic' | 'forward'
export type TlsSource = 'letsencrypt' | 'selfsigned' | 'none'
export type ServiceKind = 'raw' | 'http'
export type SecurityEventSource = 'crowdsec' | 'appsec' | 'traefik'
export type EdgePolicy = Record<string, unknown>

export interface EdgeRouteConfig {
  id: string
  port_forward_id: string
  profile_id?: string | null
  priority?: number
  policy?: EdgePolicy
  waf_mode: WafMode
  rate_limit_rps: number | null
  rate_limit_burst: number | null
  antibot: boolean
  auth_mode: AuthMode
  auth_config: Record<string, unknown> | null
  ip_allow: string[] | null
  ip_deny: string[] | null
  geo_block: string[] | null
  tls_source: TlsSource
  upstream_scheme: 'http' | 'https'
  upstream_insecure_skip_verify: boolean
  imported_router_name: string | null
  imported_service_name: string | null
  imported_middlewares: string[] | null
  import_warnings: string[] | null
  created_at: string
  updated_at: string
}

export interface ServerEdgePolicy {
  server_id: string
  agent_id: string
  rate_limit_rps: number | null
  rate_limit_burst: number | null
}

export interface SiteEffectivePolicy {
  rate_limit: {
    global: { rps: number | null; burst: number | null } | null
    site: { rps: number | null; burst: number | null } | null
  }
  middleware_chain: string[]
  warnings: string[]
}

export interface Site {
  id: string
  attachment_id: string
  tunnel_server_ip_id: string | null
  server_id: string | null
  agent_id: string | null
  protocol: 'tcp' | 'udp'
  public_port: number
  public_port_end: number | null
  destination_ip: string
  destination_port: number
  destination_port_end: number | null
  description: string | null
  active: boolean
  service_kind: ServiceKind
  domain: string | null
  created_at: string
  edge_config: EdgeRouteConfig | null
  effective_policy: SiteEffectivePolicy | null
}

export interface SiteCreate {
  attachment_id: string
  tunnel_server_ip_id?: string | null
  protocol: 'tcp' | 'udp'
  public_port: number
  destination_ip: string
  destination_port: number
  description?: string | null
  domain: string
  waf_mode?: WafMode
  rate_limit_rps?: number | null
  rate_limit_burst?: number | null
  antibot?: boolean
  auth_mode?: AuthMode
  geo_block?: string[] | null
  tls_source?: TlsSource
  upstream_scheme?: 'http' | 'https'
  upstream_insecure_skip_verify?: boolean
}

export interface SiteUpdate {
  description?: string | null
  active?: boolean
  domain?: string | null
  waf_mode?: WafMode
  rate_limit_rps?: number | null
  rate_limit_burst?: number | null
  antibot?: boolean
  auth_mode?: AuthMode
  auth_config?: Record<string, unknown> | null
  ip_allow?: string[] | null
  ip_deny?: string[] | null
  geo_block?: string[] | null
  tls_source?: TlsSource
  upstream_scheme?: 'http' | 'https'
  upstream_insecure_skip_verify?: boolean
}

export interface NodeEdgeCapabilities {
  agent_id: string
  mode: EdgeMode
  state: EdgeState
  install_phase: EdgeInstallPhase
  last_error: string | null
  unavailable_reason: string | null
  components: Record<string, EdgeComponent>
}

export interface NodeEdgeActionResult {
  sent: boolean
  command_id: string | null
  edge: NodeEdgeCapabilities
}

export interface EdgeProfile {
  id: string
  name: string
  slug: string
  description: string | null
  scope: string
  agent_id: string | null
  policy: EdgePolicy
  created_at: string
  updated_at: string
}

export interface EdgeProfileUpsert {
  name: string
  slug?: string | null
  description?: string | null
  scope?: string
  agent_id?: string | null
  policy?: EdgePolicy
}

export interface EdgeNodePolicy {
  agent_id: string
  default_profile_id: string | null
  client_ip_strategy: string
  trusted_proxy_cidrs: string[]
  cloudflare_mode: string
  access_log_retention_hours: number
  security_event_retention_days: number
  policy: EdgePolicy
  effective: EdgePolicy
}

export interface EdgeNodePolicyUpdate {
  default_profile_id?: string | null
  client_ip_strategy?: string | null
  trusted_proxy_cidrs?: string[] | null
  cloudflare_mode?: string | null
  access_log_retention_hours?: number | null
  security_event_retention_days?: number | null
  policy?: EdgePolicy | null
}

export interface EdgeRoute {
  id: string
  node_id: string
  server_id: string
  attachment_id: string
  domain: string | null
  enabled: boolean
  priority: number
  profile_id: string | null
  destination_ip: string
  destination_port: number
  description: string | null
  policy: EdgePolicy
  effective: EdgePolicy
  created_at: string
}

export interface EdgeRouteUpsert {
  attachment_id?: string | null
  enabled?: boolean | null
  priority?: number | null
  profile_id?: string | null
  profile?: string | null
  destination_ip?: string | null
  destination_port?: number | null
  description?: string | null
  policy?: EdgePolicy | null
  upstream_scheme?: 'http' | 'https' | null
  upstream_insecure_skip_verify?: boolean | null
}

export interface EdgeEffectivePolicy {
  route_id: string
  desired: EdgePolicy
  effective: EdgePolicy
  sources: Record<string, EdgePolicy>
}

export interface EdgePathRule {
  id: string
  route_id: string
  name: string
  match: EdgePolicy
  priority: number
  enabled: boolean
  policy: EdgePolicy
  effective: EdgePolicy
  created_at: string
  updated_at: string
}

export interface EdgePathRuleCreate {
  name: string
  match: EdgePolicy
  priority?: number
  enabled?: boolean
  policy?: EdgePolicy
}

export interface EdgeAccessEvent {
  id: number
  agent_id: string
  route_id: string | null
  request_id: string | null
  occurred_at: string
  host: string | null
  path: string | null
  method: string | null
  status_code: number | null
  client_ip: string | null
  client_country: string | null
  client_asn: string | null
  user_agent: string | null
  referer: string | null
  action: string
  source: string
  latency_ms: number | null
  cache_status: string | null
  upstream_url: string | null
  upstream_status: number | null
  bytes_in: number | null
  bytes_out: number | null
  matched_rule: string | null
  sampled: boolean
}

export interface EdgeAccessEventList {
  items: EdgeAccessEvent[]
  next_cursor: number | null
}

export interface EdgeCacheState {
  available: boolean
  reason: string | null
  backend: Record<string, unknown> | null
  policy: EdgePolicy
}

export interface EdgeCachePatch {
  mode: string
  browser_ttl_seconds?: number | null
  edge_ttl_seconds?: number | null
  cache_status_header?: boolean | null
}

export interface EdgeCachePurgeRequest {
  scope?: string
  route_id?: string | null
  host?: string | null
  path?: string | null
  prefix?: string | null
}

export interface EdgeFragment {
  id: string
  agent_id: string
  route_id: string | null
  name: string
  fragment_type: string
  content: EdgePolicy
  enabled: boolean
  validation_state: string
  last_error: string | null
  created_at: string
  updated_at: string
}

export interface EdgeFragmentCreate {
  name: string
  fragment_type: string
  content: EdgePolicy
  route_id?: string | null
  enabled?: boolean
}

export interface EdgeRenderedConfig {
  desired_hash: string
  static_hash: string | null
  dynamic_hash: string | null
  cache_hash: string | null
  dynamic: EdgePolicy
}

export interface EdgeConfigVersion {
  id: string
  agent_id: string
  desired_hash: string
  rendered_static_hash: string | null
  rendered_dynamic_hash: string | null
  rendered_cache_hash: string | null
  created_at: string
  applied_at: string | null
  agent_result: string | null
}

export interface EdgeDesiredStateResponse {
  dry_run: boolean
  changed: boolean
  validation_errors: EdgePolicy[]
  diff: string | null
  profiles: EdgePolicy[]
  routes: EdgePolicy[]
  effective: EdgePolicy
  reconcile_sent: boolean
}

export interface SecurityEvent {
  id: number
  agent_id: string
  source: SecurityEventSource
  kind: string
  ip: string | null
  value: string | null
  action: string | null
  raw: Record<string, unknown> | null
  occurred_at: string
}

export interface SecurityEventGroup {
  agent_id: string
  source: SecurityEventSource
  kind: string
  ip: string | null
  value: string | null
  action: string | null
  count: number
  first_seen_at: string
  last_seen_at: string
}

export interface SecurityOverviewKpis {
  access: number
  visitors: number
  blocked: number
  attack_ips: number
  err_4xx: number
  err_5xx: number
}

export interface SecurityTimePoint {
  t: string
  value: number
}

export interface SecurityTopEntry {
  name?: string
  ip?: string
  count: number
}

export interface SecurityServerStatus {
  server_id: string
  agent_id: string | null
  name: string | null
  crowdsec_running: boolean
  traefik_running: boolean
}

export interface SecurityOverview {
  kpis: SecurityOverviewKpis
  access_series: SecurityTimePoint[]
  block_series: SecurityTimePoint[]
  top_attackers: SecurityTopEntry[]
  top_scenarios: SecurityTopEntry[]
  servers: SecurityServerStatus[]
}

export interface TraefikStatus {
  installed: boolean
  running: boolean
  version: string | null
  routes_count: number
  error: string | null
  phase: 'healthy' | 'degraded' | 'pending' | 'unknown'
  last_error: string | null
  updated_at: string | null
}

export interface NodeEdge {
  agent_id: string
  mode: EdgeMode
  state: EdgeState
  phase: 'healthy' | 'degraded' | 'pending' | 'disabled' | 'unknown'
  install_phase: EdgeInstallPhase
  last_error: string | null
  unavailable_reason: string | null
  components: Record<string, EdgeComponent>
  policy: ServerEdgePolicy
  crowdsec: CrowdSecStatus
  traefik: TraefikStatus
  sites: Site[]
}

export interface TraefikImportRoutePreview {
  router_name: string
  domain: string | null
  service_name: string | null
  upstream_url: string | null
  destination_ip: string | null
  destination_port: number | null
  upstream_scheme: 'http' | 'https'
  upstream_insecure_skip_verify: boolean
  tls_source: TlsSource
  middlewares: string[]
  mapped_policy: Record<string, unknown>
  warnings: string[]
  importable: boolean
  existing_site_id: string | null
}

export interface TraefikImportPreview {
  summary: {
    routers: number
    importable: number
    skipped: number
    existing: number
  }
  routes: TraefikImportRoutePreview[]
}

export interface TraefikImportRequest {
  server_id: string
  attachment_id: string
  content: string
  middlewares_content?: string | null
  content_format?: 'auto' | 'yaml' | 'yml' | 'toml'
  domain_suffix?: string | null
  activate?: boolean
  overwrite?: boolean
}

export interface TraefikImportResult extends TraefikImportPreview {
  created: number
  updated: number
  skipped: number
}

export interface BanEntry {
  ip: string
  count: number
  source: string
}

export interface CertEntry {
  domain: string
  status: 'managed' | 'pending' | 'error'
  port_forward_id: string
}
