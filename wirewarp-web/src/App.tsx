import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { isAuthenticated, setToken } from './lib/api'
import { mountRealtime } from './lib/realtime'
import { ToastProvider, useToast } from './components/Toasts'
import { useRole } from './hooks/useRole'
import Login from './pages/Login'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import AgentDetail from './pages/AgentDetail'
import TunnelServers from './pages/TunnelServers'
import TunnelClients from './pages/TunnelClients'
import LanClients from './pages/LanClients'
import PortForwards from './pages/PortForwards'
import Settings from './pages/Settings'
import Users from './pages/Users'
import VpnEndpoints from './pages/VpnEndpoints'
import MyVpn from './pages/MyVpn'

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

// Viewers (read-only role) have nothing to do on the admin dashboard,
// so route them to /vpn where they can grab their WireGuard profile.
function ViewerHome({ children }: { children: React.ReactNode }) {
  const { role, isAdmin, isOperator, user } = useRole()
  const location = useLocation()
  if (role !== undefined && !isAdmin && !isOperator && location.pathname === '/' && user?.vpn_enabled) {
    return <Navigate to="/vpn" replace />
  }
  return <>{children}</>
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
              <Route
                index
                element={
                  <ViewerHome>
                    <Dashboard />
                  </ViewerHome>
                }
              />
              <Route path="agents" element={<Agents />} />
              <Route path="agents/:id" element={<AgentDetail />} />
              <Route path="tunnel-servers" element={<TunnelServers />} />
              <Route path="tunnel-clients" element={<TunnelClients />} />
              <Route path="lan-clients" element={<LanClients />} />
              <Route path="port-forwards" element={<PortForwards />} />
              <Route path="vpn-endpoints" element={<VpnEndpoints />} />
              <Route path="vpn" element={<MyVpn />} />
              <Route path="users" element={<Users />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}
