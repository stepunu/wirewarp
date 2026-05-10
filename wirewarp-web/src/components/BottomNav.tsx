import { NavLink } from 'react-router-dom'
import { Ic } from './icons'

export function BottomNav({ onMore }: { onMore: () => void }) {
  return (
    <nav className="bottom-nav" aria-label="Primary">
      <NavLink to="/" end className={({ isActive }) => `bn-item ${isActive ? 'active' : ''}`}>
        <Ic.dashboard s={20} />
        <span>Dash</span>
      </NavLink>
      <NavLink to="/agents" className={({ isActive }) => `bn-item ${isActive ? 'active' : ''}`}>
        <Ic.agent s={20} />
        <span>Agents</span>
      </NavLink>
      <NavLink to="/tunnel-servers" className={({ isActive }) => `bn-item ${isActive ? 'active' : ''}`}>
        <Ic.server s={20} />
        <span>Servers</span>
      </NavLink>
      <NavLink to="/port-forwards" className={({ isActive }) => `bn-item ${isActive ? 'active' : ''}`}>
        <Ic.forward s={20} />
        <span>Forwards</span>
      </NavLink>
      <button className="bn-item" onClick={onMore} aria-label="More">
        <Ic.panelL s={20} />
        <span>More</span>
      </button>
    </nav>
  )
}
