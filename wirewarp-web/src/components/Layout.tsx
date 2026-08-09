import { useEffect, useState } from 'react'
import { Outlet, useLocation, useNavigate, NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Ic } from './icons'
import { K } from './ui'
import { CommandPalette } from './CommandPalette'
import { HelpOverlay } from './HelpOverlay'
import { BottomNav } from './BottomNav'
import { useGlobalHotkeys } from '../hooks/useHotkeys'
import { useRole } from '../hooks/useRole'
import { agents as agentsApi, auth as authApi, nodes as nodesApi, portForwards as pfApi, clearToken } from '../lib/api'

import type { Role } from '../lib/types'

type NavEntry = {
  path: string
  label: string
  icon: typeof Ic.dashboard
  exact?: boolean
  // Roles allowed to see this entry. If omitted = visible to all auth'd users.
  roles?: Role[]
  // Additionally requires user.vpn_enabled flag.
  vpnEnabledOnly?: boolean
}
const NAV: NavEntry[] = [
  { path: '/', label: 'Dashboard', icon: Ic.dashboard, exact: true },
  { path: '/nodes', label: 'Nodes', icon: Ic.agent, roles: ['admin', 'operator', 'viewer'] },
  { path: '/lan-clients', label: 'LAN clients', icon: Ic.host, roles: ['admin', 'operator', 'viewer'] },
  { path: '/port-forwards', label: 'Port forwards', icon: Ic.forward, roles: ['admin', 'operator', 'viewer'] },
  { path: '/vpn-endpoints', label: 'VPN endpoints', icon: Ic.client, roles: ['admin', 'operator'] },
  { path: '/vpn', label: 'My VPN', icon: Ic.client, vpnEnabledOnly: true },
  { path: '/users', label: 'Users', icon: Ic.settings, roles: ['admin'] },
  { path: '/settings', label: 'Settings', icon: Ic.settings, roles: ['admin'] },
]

const SECURITY_NAV: NavEntry[] = [
  { path: '/security', label: 'Overview', icon: Ic.chart, exact: true, roles: ['admin', 'operator', 'viewer'] },
  { path: '/security/events', label: 'Events', icon: Ic.alert, roles: ['admin', 'operator', 'viewer'] },
  { path: '/security/bans', label: 'Bans', icon: Ic.ban, roles: ['admin', 'operator', 'viewer'] },
  { path: '/security/certs', label: 'Certs', icon: Ic.cert, roles: ['admin', 'operator', 'viewer'] },
]

function getInitialTheme(): 'dark' | 'light' {
  const saved = localStorage.getItem('theme')
  return saved === 'light' ? 'light' : 'dark'
}

function pathToCrumb(path: string): string {
  if (path === '/') return 'overview'
  return path.replace(/^\//, '').replace(/\//g, '/')
}

export default function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)
  const [theme, setTheme] = useState<'dark' | 'light'>(getInitialTheme)
  const [cmdkOpen, setCmdkOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('theme', theme)
  }, [theme])

  // Tag <html> with .mobile so CSS can switch shell layout. Re-evaluated
  // on resize (debounced) so hot-rotating a tablet works without reload.
  useEffect(() => {
    const apply = () => {
      document.documentElement.classList.toggle('mobile', window.innerWidth < 768)
    }
    apply()
    let t: number | undefined
    const onResize = () => {
      if (t) window.clearTimeout(t)
      t = window.setTimeout(apply, 150)
    }
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      if (t) window.clearTimeout(t)
    }
  }, [])

  // Auto-close mobile drawer on route change.
  useEffect(() => {
    setDrawerOpen(false)
  }, [location.pathname])

  const agentsQ = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,

    staleTime: 4000,
  })
  const nodesQ = useQuery({
    queryKey: ['nodes'],
    queryFn: nodesApi.list,
    staleTime: 4000,
  })
  const pfQ = useQuery({
    queryKey: ['port-forwards'],
    queryFn: () => pfApi.list(),
  })
  const { user, role } = useRole()
  const visibleNav = NAV.filter((n) => {
    if (n.roles && (!role || !n.roles.includes(role))) return false
    if (n.vpnEnabledOnly && !user?.vpn_enabled) return false
    return true
  })

  useGlobalHotkeys({
    onCmdK: () => setCmdkOpen(true),
    onHelp: () => setHelpOpen(true),
    navigate,
    active: !cmdkOpen && !helpOpen,
  })

  const visibleSecurityNav = SECURITY_NAV.filter((n) => {
    if (n.roles && (!role || !n.roles.includes(role))) return false
    return true
  })

  const agents = agentsQ.data ?? []
  const nodes = nodesQ.data ?? []
  const pfCount = pfQ.data?.length ?? 0
  const crumb = pathToCrumb(location.pathname)

  async function logout() {
    try {
      await authApi.logout()
    } catch {
      // Audit-only; ignore failures and clear locally regardless.
    }
    clearToken()
    navigate('/login')
  }

  return (
    <div className={`app-grid ${collapsed ? 'collapsed' : ''} ${drawerOpen ? 'drawer-open' : ''}`}>
      {drawerOpen && <div className="sb-scrim" onClick={() => setDrawerOpen(false)} />}
      <aside className={`sb ${drawerOpen ? 'drawer-open' : ''}`}>
        <div className="sb-brand">
          <img className="logo" src="/logo.svg" alt="" width={22} height={22} />
          <span className="scheme">wire://</span>
          <span className="name">wirewarp</span>
        </div>
        <div className="sb-section">Operate</div>
        <nav className="sb-nav">
          {visibleNav.map((p) => (
            <NavLink
              key={p.path}
              to={p.path}
              end={p.exact}
              className={({ isActive }) => `sb-link ${isActive ? 'active' : ''}`}
            >
              <p.icon s={14} />
              <span>{p.label}</span>
              {p.path === '/nodes' && <span className="badge">{nodes.length}</span>}
              {p.path === '/port-forwards' && <span className="badge">{pfCount}</span>}
            </NavLink>
          ))}
        </nav>
        {visibleSecurityNav.length > 0 && (
          <>
            <div className="sb-section">Security</div>
            <nav className="sb-nav">
              {visibleSecurityNav.map((p) => (
                <NavLink
                  key={p.path}
                  to={p.path}
                  end={p.exact}
                  className={({ isActive }) => `sb-link ${isActive ? 'active' : ''}`}
                >
                  <p.icon s={14} />
                  <span>{p.label}</span>
                </NavLink>
              ))}
            </nav>
          </>
        )}
        <div className="sb-foot">
          <button className="sb-link" onClick={() => setHelpOpen(true)}>
            <Ic.help s={14} />
            <span>Shortcuts</span>
            <span className="badge">?</span>
          </button>
          <div className="ws-status">
            <span className={`dot ${agentsQ.isError ? 'err' : 'ok'}`}></span>
            <span className="label">{agentsQ.isError ? 'api · offline' : 'api · polling'}</span>
          </div>
        </div>
      </aside>

      <header className="tb">
        <button
          className="tb-collapse"
          onClick={() => setCollapsed((c) => !c)}
          title="Collapse sidebar"
        >
          <Ic.panelL />
        </button>
        <button
          className="tb-hamburger"
          onClick={() => setDrawerOpen((o) => !o)}
          aria-label="Open navigation"
        >
          <Ic.panelL />
        </button>
        <div className="crumbs">
          <span className="scheme">wire://wirewarp</span>
          <span className="sep">/</span>
          <span className="here">{crumb}</span>
        </div>
        <div className="tb-spacer"></div>
        <button className="cmdk-trigger" onClick={() => setCmdkOpen(true)}>
          <Ic.search s={12} />
          <span className="placeholder">Jump to anywhere…</span>
          <K>⌘K</K>
        </button>
        <button
          className="tb-icon-btn"
          onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
          title="Toggle theme"
        >
          {theme === 'dark' ? <Ic.moon /> : <Ic.sun />}
        </button>
        <button className="tb-icon-btn" onClick={() => setHelpOpen(true)} title="Help">
          <Ic.help />
        </button>
        <button className="user-menu" onClick={logout} title="Sign out">
          <span className="avatar">{(user?.username ?? 'A').slice(0, 1).toUpperCase()}</span>
          <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1, alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12 }}>{user?.username ?? '…'}</span>
            <span className="scheme" style={{ fontSize: 10 }}>{role ?? '—'}</span>
          </div>
        </button>
      </header>

      <main className="main">
        <Outlet />
      </main>

      {role && role !== 'vpn_user' && <BottomNav onMore={() => setDrawerOpen(true)} />}

      {cmdkOpen && (
        <CommandPalette
          onClose={() => setCmdkOpen(false)}
          navigate={navigate}
          agents={agents}
          canIssueAgentToken={role === 'admin'}
        />
      )}
      {helpOpen && <HelpOverlay onClose={() => setHelpOpen(false)} />}
    </div>
  )
}
