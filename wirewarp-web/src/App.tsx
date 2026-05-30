import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { isAuthenticated, setToken, tunnelClients as tcApi, tunnelServers as tsApi } from './lib/api'
import { mountRealtime } from './lib/realtime'
import { ToastProvider, useToast } from './components/Toasts'
import { useRole } from './hooks/useRole'
import type { Role } from './lib/types'
import Login from './pages/Login'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Nodes from './pages/Nodes'
import NodeDetail from './pages/NodeDetail'
import LanClients from './pages/LanClients'
import PortForwards from './pages/PortForwards'
import Settings from './pages/Settings'
import Users from './pages/Users'
import VpnEndpoints from './pages/VpnEndpoints'
import MyVpn from './pages/MyVpn'
import SecurityOverview from './pages/SecurityOverview'
import SecurityEvents from './pages/SecurityEvents'
import SecurityBans from './pages/SecurityBans'
import SecurityCerts from './pages/SecurityCerts'

// OIDC callback redirects to `/#token=<jwt>`. Pull the token out of the
// URL fragment, store it, and replace the URL so the secret doesn't sit
// in browser history. Run before the BrowserRouter mounts so the next
// render already sees the authenticated state.
function consumeOidcCallback() {
  if (typeof window === 'undefined') return
  const hash = window.location.hash
  const m = hash.match(/(?:^|[?&#])token=([^&]+)/)
  if (m) {
    setToken(decodeURIComponent(m[1]))
    const cleaned = window.location.pathname + window.location.search
    window.history.replaceState({}, '', cleaned)
  }
}
consumeOidcCallback()

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const push = useToast()
  // Mount the realtime channel once we're inside the auth wall. The
  // hook reads the token via getToken at WS open time, so it picks up
  // a freshly-set token after a successful login without remount.
  useEffect(() => {
    return mountRealtime({
      queryClient,
      getToken: () => localStorage.getItem('token'),
      onEvent: (e) => {
        // Surface DNS sync outcomes as toasts. Manual-update notice
        // matters most: it tells operators on non-Cloudflare setups
        // exactly which records to update by hand.
        const t = e.type as string
        if (t === 'dns.synced') {
          const records = (e.records as string[] | undefined) ?? []
          push(`DNS updated → ${e.new_ip}: ${records.join(', ')}`, 'ok', 'dns://')
        } else if (t === 'dns.sync_failed') {
          const fails = (e.failures as { name: string; error: string }[] | undefined) ?? []
          push(`DNS update failed: ${fails.map((f) => f.name).join(', ')}`, 'err', 'dns://')
        } else if (t === 'dns.manual_update_needed') {
          const records = (e.records as string[] | undefined) ?? []
          push(
            `Egress moved → ${e.new_ip}. Update DNS manually: ${records.join(', ')}`,
            'info',
            'dns://',
          )
        }
      },
    })
  }, [push])
  if (!isAuthenticated()) return <Navigate to="/login" replace />
  return <>{children}</>
}

// Restrict a route to specific roles. While role is loading we render
// nothing to avoid flashing the page or a redirect. If the user's role
// isn't allowed, send them to a safe page they can see — vpn_user with
// VPN enabled to /vpn, everyone else to / (Dashboard, visible to all).
function RoleGuard({ allow, children }: { allow: Role[]; children: React.ReactNode }) {
  const { role, user } = useRole()
  const location = useLocation()
  if (role === undefined) return null
  if (!allow.includes(role)) {
    if (role === 'vpn_user' && user?.vpn_enabled) {
      return <Navigate to="/vpn" replace />
    }
    if (location.pathname !== '/') return <Navigate to="/" replace />
  }
  return <>{children}</>
}

function ServerNodeRedirect() {
  const { id } = useParams<{ id: string }>()
  const q = useQuery({ queryKey: ['tunnel-server', id], queryFn: () => tsApi.get(id!), enabled: !!id })
  if (!id) return <Navigate to="/nodes" replace />
  if (q.data) return <Navigate to={`/nodes/${q.data.agent_id}`} replace />
  return null
}

function ClientNodeRedirect() {
  const { id } = useParams<{ id: string }>()
  const q = useQuery({ queryKey: ['tunnel-client', id], queryFn: () => tcApi.get(id!), enabled: !!id })
  if (!id) return <Navigate to="/nodes" replace />
  if (q.data) return <Navigate to={`/nodes/${q.data.agent_id}`} replace />
  return null
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route
                path="nodes"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <Nodes />
                  </RoleGuard>
                }
              />
              <Route
                path="nodes/:id"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <NodeDetail />
                  </RoleGuard>
                }
              />
              <Route path="agents" element={<Navigate to="/nodes" replace />} />
              <Route path="agents/:id" element={<NavigateToNodeParam />} />
              <Route
                path="tunnel-servers"
                element={<Navigate to="/nodes" replace />}
              />
              <Route
                path="tunnel-servers/:id"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <ServerNodeRedirect />
                  </RoleGuard>
                }
              />
              <Route
                path="tunnel-clients"
                element={<Navigate to="/nodes" replace />}
              />
              <Route
                path="tunnel-clients/:id"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <ClientNodeRedirect />
                  </RoleGuard>
                }
              />
              <Route
                path="lan-clients"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <LanClients />
                  </RoleGuard>
                }
              />
              <Route
                path="port-forwards"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <PortForwards />
                  </RoleGuard>
                }
              />
              <Route
                path="vpn-endpoints"
                element={
                  <RoleGuard allow={['admin', 'operator']}>
                    <VpnEndpoints />
                  </RoleGuard>
                }
              />
              <Route path="vpn" element={<MyVpn />} />
              <Route
                path="users"
                element={
                  <RoleGuard allow={['admin']}>
                    <Users />
                  </RoleGuard>
                }
              />
              <Route
                path="settings"
                element={
                  <RoleGuard allow={['admin']}>
                    <Settings />
                  </RoleGuard>
                }
              />
              <Route
                path="security"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <SecurityOverview />
                  </RoleGuard>
                }
              />
              <Route
                path="security/events"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <SecurityEvents />
                  </RoleGuard>
                }
              />
              <Route
                path="security/sites"
                element={<Navigate to="/nodes" replace />}
              />
              <Route
                path="security/protections"
                element={<Navigate to="/nodes" replace />}
              />
              <Route
                path="security/bans"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <SecurityBans />
                  </RoleGuard>
                }
              />
              <Route
                path="security/certs"
                element={
                  <RoleGuard allow={['admin', 'operator', 'viewer']}>
                    <SecurityCerts />
                  </RoleGuard>
                }
              />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

function NavigateToNodeParam() {
  const { id } = useParams<{ id: string }>()
  return <Navigate to={id ? `/nodes/${id}` : '/nodes'} replace />
}
