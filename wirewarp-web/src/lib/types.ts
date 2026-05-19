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
