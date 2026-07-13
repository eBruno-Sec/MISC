import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import MissionList from './components/MissionList'
import MissionLaunch from './components/MissionLaunch'
import MissionControl from './components/MissionControl'
import Oracle from './components/Oracle'

function Header() {
  const [light, setLight] = useState(() => localStorage.getItem('yggdrasil_theme') === 'light')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', light ? 'light' : '')
    localStorage.setItem('yggdrasil_theme', light ? 'light' : 'dark')
  }, [light])

  return (
    <header style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 2rem', height: '52px',
      background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      position: 'sticky', top: 0, zIndex: 100,
    }}>
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none' }}>
        <span style={{ fontFamily: 'var(--display)', fontWeight: 900, fontSize: '1.2rem', color: 'var(--accent)' }}>Y</span>
        <span style={{ fontFamily: 'var(--display)', fontWeight: 900, fontSize: '1.1rem', color: 'var(--text-bright)', letterSpacing: '0.05em' }}>YGGDRASIL</span>
        <span style={{ fontSize: '0.6rem', letterSpacing: '0.25em', color: 'var(--text-dim)', marginLeft: '0.25rem' }}>AUTHORIZED SECURITY WORKSPACE</span>
      </Link>
      <nav style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <button
          onClick={() => setLight(l => !l)}
          title={light ? 'Switch to dark mode' : 'Switch to light mode'}
          aria-label={light ? 'Switch to dark mode' : 'Switch to light mode'}
          style={{
            fontSize: '0.72rem', letterSpacing: '0.15em', padding: '0.4rem 0.8rem',
            border: '1px solid var(--border2)', color: 'var(--text-dim)',
            background: 'transparent', cursor: 'pointer', transition: 'all 0.15s',
          }}
        >
          {light ? 'DARK' : 'LIGHT'}
        </button>
        <Link
          to="/oracle"
          style={{
            fontSize: '0.72rem', letterSpacing: '0.2em', padding: '0.4rem 1.1rem',
            border: '1px solid var(--border2)', color: 'var(--text-dim)',
            background: 'transparent', textDecoration: 'none', transition: 'all 0.15s',
          }}
        >
          ORACLE
        </Link>
        <Link
          to="/launch"
          style={{
            fontSize: '0.72rem', letterSpacing: '0.2em', padding: '0.4rem 1.1rem',
            border: '1px solid var(--accent)', color: 'var(--accent)',
            background: 'var(--accent-dim)', textDecoration: 'none', transition: 'all 0.15s',
          }}
        >
          + NEW MISSION
        </Link>
      </nav>
    </header>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Header />
      <Routes>
        <Route path="/" element={<MissionList />} />
        <Route path="/launch" element={<MissionLaunch />} />
        <Route path="/mission/:id" element={<MissionControl />} />
        <Route path="/oracle" element={<Oracle />} />
      </Routes>
    </BrowserRouter>
  )
}