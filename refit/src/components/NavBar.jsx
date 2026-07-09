import { Link, useLocation } from 'react-router-dom'
import { supabase } from '../lib/supabase'

export default function NavBar() {
  const { pathname } = useLocation()

  return (
    <nav className="nav-bar">
      <Link to="/" className={`nav-item ${pathname === '/' ? 'active' : ''}`}>
        <span className="nav-icon">🏰</span>
        <span className="pixel-text nav-label">BASE</span>
      </Link>
      <Link to="/workout" className={`nav-item ${pathname === '/workout' ? 'active' : ''}`}>
        <span className="nav-icon">⚔️</span>
        <span className="pixel-text nav-label">QUEST</span>
      </Link>
      <Link to="/harem" className={`nav-item ${pathname === '/harem' ? 'active' : ''}`}>
        <span className="nav-icon">💕</span>
        <span className="pixel-text nav-label">PARTY</span>
      </Link>
      <button className="nav-item" onClick={() => supabase.auth.signOut()}>
        <span className="nav-icon">🚪</span>
        <span className="pixel-text nav-label">EXIT</span>
      </button>
    </nav>
  )
}
