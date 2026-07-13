import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import MissionList from './components/MissionList'
import MissionLaunch from './components/MissionLaunch'
import MissionControl from './components/MissionControl'
import { PRODUCT_NAME, PRODUCT_TAGLINE } from './brand'

function Header() {
  return (
    <header className="topbar">
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', textDecoration: 'none' }}>
        <span className="brand-mark">YG</span>
        <span style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
          <span style={{ fontWeight: 850, fontSize: '1.1rem', color: 'var(--text-bright)' }}>{PRODUCT_NAME}</span>
          <span className="topbar-subtitle" style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.18rem' }}>
            {PRODUCT_TAGLINE}
          </span>
        </span>
      </Link>
      <Link to="/launch" className="primary-action">
        New Assessment
      </Link>
    </header>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Header />
        <Routes>
          <Route path="/" element={<MissionList />} />
          <Route path="/launch" element={<MissionLaunch />} />
          <Route path="/mission/:id" element={<MissionControl />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
