export interface User {
  id: string
  username: string
  email: string
  role: string
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
  token: string
  agent_type: string
  used: boolean
  expires_at: string
  created_at: string
}

export interface TunnelServer {
  id: string
  agent_id: string
  wg_port: number
  wg_interface: string
  public_ip: string | null
  public_iface: string
  wg_public_key: string | null
  tunnel_network: string
  created_at: string
}

export interface TunnelClient {
  id: string
  agent_id: string
  tunnel_server_id: string | null
  tunnel_ip: string | null
  vm_network: string | null
  lan_ip: string | null
  is_gateway: boolean
  wg_public_key: string | null
  status: string
  created_at: string
}

export interface PortForward {
  id: string
  tunnel_server_id: string
  tunnel_client_id: string
  protocol: 'tcp' | 'udp'
  public_port: number
  destination_ip: string
  destination_port: number
  description: string | null
  active: boolean
  created_at: string
}

export interface ServiceTemplate {
  id: string
  name: string
  protocol: string
  ports: string
  is_builtin: boolean
  created_at: string
}

export interface SystemSettings {
  public_url: string | null
  internal_url: string | null
  instance_name: string
  agent_token_expiry_hours: number
}
