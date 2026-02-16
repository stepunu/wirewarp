import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { clearToken } from '../lib/api'

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/agents', label: 'Agents' },
  { to: '/tunnel-servers', label: 'Tunnel Servers' },
  { to: '/tunnel-clients', label: 'Tunnel Clients' },
  { to: '/port-forwards', label: 'Port Forwards' },
]

export default function Layout() {
  const navigate = useNavigate()

  function logout() {
    clearToken()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <nav className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-between h-14">
          <div className="flex items-center gap-6">
            <span className="text-lg font-bold text-white tracking-tight">WireWarp</span>
            <div className="flex gap-1">
              {links.map((l) => (
                <NavLink
                  key={l.to}
                  to={l.to}
                  end={l.to === '/'}
                  className={({ isActive }) =>
                    `px-3 py-1.5 rounded text-sm ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800'
                    }`
                  }
                >
                  {l.label}
                </NavLink>
              ))}
            </div>
          </div>
          <button
            onClick={logout}
            className="text-sm text-gray-400 hover:text-white"
          >
            Logout
          </button>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
