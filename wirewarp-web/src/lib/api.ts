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
  me: () => request<{ id: string; username: string; email: string; role: string }>('/auth/me'),
}

// Agents
export const agents = {
  list: () => request<import('./types').Agent[]>('/agents'),
  get: (id: string) => request<import('./types').Agent>(`/agents/${id}`),
  del: (id: string) => request<void>(`/agents/${id}`, { method: 'DELETE' }),
  createToken: (agent_type: string) =>
    request<import('./types').RegistrationToken>('/agents/tokens', {
      method: 'POST',
      body: JSON.stringify({ agent_type }),
    }),
}

// Tunnel Servers
export const tunnelServers = {
  list: () => request<import('./types').TunnelServer[]>('/tunnel-servers'),
  get: (id: string) => request<import('./types').TunnelServer>(`/tunnel-servers/${id}`),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').TunnelServer>(`/tunnel-servers/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
}

// Tunnel Clients
export const tunnelClients = {
  list: () => request<import('./types').TunnelClient[]>('/tunnel-clients'),
  get: (id: string) => request<import('./types').TunnelClient>(`/tunnel-clients/${id}`),
  update: (id: string, data: Record<string, unknown>) =>
    request<import('./types').TunnelClient>(`/tunnel-clients/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
}

// Port Forwards
export const portForwards = {
  list: (tunnelServerId?: string) =>
    request<import('./types').PortForward[]>(
      `/port-forwards${tunnelServerId ? `?tunnel_server_id=${tunnelServerId}` : ''}`
    ),
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
