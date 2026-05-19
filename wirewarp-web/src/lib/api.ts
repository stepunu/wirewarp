const API_BASE = '/api'

function getToken(): string | null {
  return localStorage.getItem('token')
}

export function setToken(token: string) {
  localStorage.setItem('token', token)
}

export function clearToken() {
  localStorage.removeItem('token')
}

export function isAuthenticated(): boolean {
  return !!getToken()
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (res.status === 401) {
    clearToken()
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status}: ${body}`)
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

// Auth
export const auth = {
  login: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  ldapLogin: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>('/auth/ldap/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  me: () => request<import('./types').User>('/auth/me'),
  providers: () =>
    request<{ active_provider: import('./types').AuthProvider }>('/auth/providers'),
}

// Admin user management
export const users = {
  list: () => request<import('./types').User[]>('/users'),
  create: (data: {
    username: string
    email: string
    password: string
    role: import('./types').Role
  }) =>
    request<import('./types').User>('/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  patch: (
    id: string,
    data: { role?: import('./types').Role; is_active?: boolean },
  ) =>
    request<import('./types').User>(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) => request<void>(`/users/${id}`, { method: 'DELETE' }),
}

// Agents
export const agents = {
  list: () => request<import('./types').Agent[]>('/agents'),
  get: (id: string) => request<import('./types').Agent>(`/agents/${id}`),
  del: (id: string) => request<void>(`/agents/${id}`, { method: 'DELETE' }),
  createToken: (agent_type: string) =>
    request<import('./types').RegistrationTokenIssued>('/agents/tokens', {
      method: 'POST',
      body: JSON.stringify({ agent_type }),
    }),
  issueJwt: (id: string) =>
    request<{ agent_id: string; jwt: string }>(`/agents/${id}/issue-jwt`, { method: 'POST' }),
  update: (id: string) =>
    request<{ command_id: string }>(`/agents/${id}/update`, { method: 'POST' }),
  healEvents: (id: string, limit = 50) =>
    request<import('./types').HealEvent[]>(`/agents/${id}/heal-events?limit=${limit}`),
}

// Tunnel Servers
export const tunnelServers = {
  list: () => request<import('./types').TunnelServer[]>('/tunnel-servers'),
  get: (id: string) => request<import('./types').TunnelServer>(`/tunnel-servers/${id}`),
  summary: (id: string) =>
    request<import('./types').TunnelServerSummary>(`/tunnel-servers/${id}/summary`),
  wgPeers: (id: string) =>
    request<import('./types').WgPeerSnapshot[]>(`/tunnel-servers/${id}/wg-peers`),
  crowdsec: (id: string) =>
    request<import('./types').CrowdSecStatus>(`/tunnel-servers/${id}/crowdsec`),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').TunnelServer>(`/tunnel-servers/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) => request<void>(`/tunnel-servers/${id}`, { method: 'DELETE' }),
  rebaseSuggestion: (id: string) =>
    request<{ tunnel_network: string }>(`/tunnel-servers/${id}/rebase-suggestion`),
  rebase: (id: string, tunnel_network: string) =>
    request<import('./types').TunnelServer>(`/tunnel-servers/${id}/rebase`, {
      method: 'POST',
      body: JSON.stringify({ tunnel_network }),
    }),
}

// Tunnel Server IPs
export const tunnelServerIPs = {
  list: (tunnelServerId?: string) =>
    request<import('./types').TunnelServerIP[]>(
      `/tunnel-server-ips${tunnelServerId ? `?tunnel_server_id=${tunnelServerId}` : ''}`
    ),
  create: (data: Record<string, unknown>) =>
    request<import('./types').TunnelServerIP>('/tunnel-server-ips', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').TunnelServerIP>(`/tunnel-server-ips/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) => request<void>(`/tunnel-server-ips/${id}`, { method: 'DELETE' }),
}

// Tunnel Clients
export const tunnelClients = {
  list: () => request<import('./types').TunnelClient[]>('/tunnel-clients'),
  get: (id: string) => request<import('./types').TunnelClient>(`/tunnel-clients/${id}`),
  summary: (id: string) =>
    request<import('./types').TunnelClientSummary>(`/tunnel-clients/${id}/summary`),
  wgPeers: (id: string) =>
    request<import('./types').WgPeerSnapshot[]>(`/tunnel-clients/${id}/wg-peers`),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').TunnelClient>(`/tunnel-clients/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) => request<void>(`/tunnel-clients/${id}`, { method: 'DELETE' }),
}

// Tunnel Client Attachments
export const tunnelClientAttachments = {
  list: (params: { tunnel_client_id?: string; tunnel_server_id?: string } = {}) => {
    const q = new URLSearchParams()
    if (params.tunnel_client_id) q.set('tunnel_client_id', params.tunnel_client_id)
    if (params.tunnel_server_id) q.set('tunnel_server_id', params.tunnel_server_id)
    const qs = q.toString()
    return request<import('./types').TunnelClientAttachment[]>(
      `/tunnel-client-attachments${qs ? `?${qs}` : ''}`
    )
  },
  get: (id: string) =>
    request<import('./types').TunnelClientAttachment>(`/tunnel-client-attachments/${id}`),
  create: (data: { tunnel_client_id: string; tunnel_server_id: string; tunnel_ip?: string }) =>
    request<import('./types').TunnelClientAttachment>('/tunnel-client-attachments', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  update: (id: string, data: { tunnel_ip?: string }) =>
    request<import('./types').TunnelClientAttachment>(`/tunnel-client-attachments/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string, opts: { cascade?: boolean } = {}) =>
    request<void>(
      `/tunnel-client-attachments/${id}${opts.cascade ? '?cascade=1' : ''}`,
      { method: 'DELETE' }
    ),
}

// LAN Clients (per gateway)
export const lanClients = {
  listAll: () => request<import('./types').LanClient[]>('/lan-clients'),
  list: (tunnelClientId: string) =>
    request<import('./types').LanClient[]>(
      `/tunnel-clients/${tunnelClientId}/lan-clients`
    ),
  create: (
    tunnelClientId: string,
    data: {
      lan_ip: string
      mac?: string
      hostname?: string
      egress_attachment_id?: string | null
      egress_tunnel_server_ip_id?: string | null
      dns_record_ids?: import('./types').DnsRecordRef[]
    },
  ) =>
    request<import('./types').LanClient>(
      `/tunnel-clients/${tunnelClientId}/lan-clients`,
      { method: 'POST', body: JSON.stringify(data) },
    ),
  setEgress: (
    tunnelClientId: string,
    lanClientId: string,
    egress_attachment_id: string | null,
    egress_tunnel_server_ip_id: string | null = null,
  ) =>
    request<import('./types').LanClient>(
      `/tunnel-clients/${tunnelClientId}/lan-clients/${lanClientId}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ egress_attachment_id, egress_tunnel_server_ip_id }),
      },
    ),
  updateMeta: (
    tunnelClientId: string,
    lanClientId: string,
    data: { hostname?: string; mac?: string },
  ) =>
    request<import('./types').LanClient>(
      `/tunnel-clients/${tunnelClientId}/lan-clients/${lanClientId}`,
      { method: 'PATCH', body: JSON.stringify(data) },
    ),
  setDnsRecords: (
    tunnelClientId: string,
    lanClientId: string,
    dns_record_ids: import('./types').DnsRecordRef[] | null,
  ) =>
    request<import('./types').LanClient>(
      `/tunnel-clients/${tunnelClientId}/lan-clients/${lanClientId}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ dns_record_ids }),
      },
    ),
  del: (tunnelClientId: string, lanClientId: string) =>
    request<void>(
      `/tunnel-clients/${tunnelClientId}/lan-clients/${lanClientId}`,
      { method: 'DELETE' },
    ),
}

// DNS provider helpers
export const dns = {
  zones: () =>
    request<{ id: string; name: string }[]>('/lan-clients/dns/zones'),
  discover: (zone_id: string, ip: string) => {
    const q = new URLSearchParams({ zone_id, ip }).toString()
    return request<import('./types').DnsRecordRef[]>(
      `/lan-clients/dns/discover?${q}`,
    )
  },
}

// Port Forwards
export const portForwards = {
  list: (params: { attachment_id?: string; tunnel_server_id?: string } = {}) => {
    const q = new URLSearchParams()
    if (params.attachment_id) q.set('attachment_id', params.attachment_id)
    if (params.tunnel_server_id) q.set('tunnel_server_id', params.tunnel_server_id)
    const qs = q.toString()
    return request<import('./types').PortForward[]>(
      `/port-forwards${qs ? `?${qs}` : ''}`
    )
  },
  create: (data: Record<string, unknown>) =>
    request<import('./types').PortForward>('/port-forwards', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').PortForward>(`/port-forwards/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) => request<void>(`/port-forwards/${id}`, { method: 'DELETE' }),
  classify: (protocol: 'tcp' | 'udp', port: number, portEnd?: number | null) => {
    const q = new URLSearchParams({ protocol, port: String(port) })
    if (portEnd) q.set('port_end', String(portEnd))
    return request<{ tip: import('./types').SensitiveServiceTip | null }>(
      `/port-forwards/classify?${q.toString()}`,
    )
  },
}

// Settings
export const settings = {
  get: () => request<import('./types').SystemSettings>('/settings'),
  update: (data: import('./types').SystemSettingsUpdate) =>
    request<import('./types').SystemSettings>('/settings', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  testAuthConnection: (
    provider: import('./types').AuthProvider,
    config?: import('./types').OidcConfig | import('./types').LdapConfig,
  ) =>
    request<{ ok: boolean; detail: string }>('/settings/auth/test', {
      method: 'POST',
      body: JSON.stringify({ provider, config: config ?? null }),
    }),
}

// Service Templates
export const serviceTemplates = {
  list: () => request<import('./types').ServiceTemplate[]>('/service-templates'),
  create: (data: Record<string, unknown>) =>
    request<import('./types').ServiceTemplate>('/service-templates', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
}

// VPN endpoints (admin)
export const vpnEndpoints = {
  list: () => request<import('./types').VpnEndpoint[]>('/vpn-endpoints'),
  get: (id: string) =>
    request<import('./types').VpnEndpoint>(`/vpn-endpoints/${id}`),
  wgPeers: (id: string) =>
    request<import('./types').WgPeerSnapshot[]>(`/vpn-endpoints/${id}/wg-peers`),
  create: (data: {
    tunnel_client_id: string
    public_endpoint: string
    listen_port?: number
    wg_interface?: string
    dns_servers?: string[] | null
  }) =>
    request<import('./types').VpnEndpoint>('/vpn-endpoints', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  update: (
    id: string,
    data: Partial<{
      public_endpoint: string
      listen_port: number
      dns_servers: string[] | null
      enabled: boolean
    }>,
  ) =>
    request<import('./types').VpnEndpoint>(`/vpn-endpoints/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) =>
    request<void>(`/vpn-endpoints/${id}`, { method: 'DELETE' }),
  // Per-(user, endpoint) permissions:
  listPermissions: (endpointId: string) =>
    request<import('./types').VpnUserPermissions[]>(
      `/vpn-endpoints/${endpointId}/permissions`,
    ),
  setUserPermissions: (
    endpointId: string,
    userId: string,
    permissions: import('./types').VpnPermissionInput[],
  ) =>
    request<import('./types').VpnPermission[]>(
      `/vpn-endpoints/${endpointId}/users/${userId}/permissions`,
      {
        method: 'PUT',
        body: JSON.stringify({ permissions }),
      },
    ),
}

// VPN profiles (mixed admin + self-serve)
export const vpnProfiles = {
  // Self-serve
  listMine: () => request<import('./types').VpnProfile[]>('/vpn-profiles/me'),
  createMine: (data: {
    vpn_endpoint_id: string
    label: string
    tunnel_mode: import('./types').VpnTunnelMode
  }) =>
    request<import('./types').VpnProfileIssued>('/vpn-profiles/me', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  regenerateMine: (id: string) =>
    request<import('./types').VpnProfileIssued>(
      `/vpn-profiles/me/${id}/regenerate`,
      { method: 'POST' },
    ),
  deleteMine: (id: string) =>
    request<void>(`/vpn-profiles/me/${id}`, { method: 'DELETE' }),

  // Admin
  list: (params: { user_id?: string; endpoint_id?: string } = {}) => {
    const q = new URLSearchParams()
    if (params.user_id) q.set('user_id', params.user_id)
    if (params.endpoint_id) q.set('endpoint_id', params.endpoint_id)
    const qs = q.toString()
    return request<import('./types').VpnProfile[]>(
      `/vpn-profiles${qs ? `?${qs}` : ''}`,
    )
  },
  create: (data: {
    user_id: string
    vpn_endpoint_id: string
    label: string
    tunnel_mode: import('./types').VpnTunnelMode
  }) =>
    request<import('./types').VpnProfileIssued>('/vpn-profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  patch: (
    id: string,
    data: { label?: string; tunnel_mode?: import('./types').VpnTunnelMode },
  ) =>
    request<import('./types').VpnProfile>(`/vpn-profiles/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  del: (id: string) =>
    request<void>(`/vpn-profiles/${id}`, { method: 'DELETE' }),
}

// Audit log
export const audit = {
  list: (params: { limit?: number; agent_id?: string; event_type?: string } = {}) => {
    const q = new URLSearchParams()
    if (params.limit != null) q.set('limit', String(params.limit))
    if (params.agent_id) q.set('agent_id', params.agent_id)
    if (params.event_type) q.set('event_type', params.event_type)
    const qs = q.toString()
    return request<import('./types').AuditEntry[]>(`/audit${qs ? `?${qs}` : ''}`)
  },
}
