import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionMode } from '../types'

const MODES: { id: MissionMode; label: string; desc: string; gates: string[] }[] = [
  {
    id: 'passive',
    label: 'PASSIVE',
    desc: 'OSINT only. Hermes maps attack surface via CT logs, DNS, WHOIS, live host detection.',
    gates: [],
  },
  {
    id: 'active',
    label: 'ACTIVE',
    desc: 'Passive recon + Ares runs Nmap and Nuclei templates on live targets.',
    gates: ['ARES activation'],
  },
  {
    id: 'full',
    label: 'FULL',
    desc: 'Complete assessment: recon → scanning → Hephaestus payload forge → Hades post-exploit analysis.',
    gates: ['ARES activation', 'HEPHAESTUS activation', 'HADES activation'],
  },
]

const GODS = ['⚡ ZEUS', '🦉 ATHENA', '☿ HERMES', '⚔ ARES', '🔥 HEPHAESTUS', '💀 HADES', '☀ APOLLO']

export default function MissionLaunch() {
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState<MissionMode>('passive')
  const [scope, setScope] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const launch = async () => {
    if (!target.trim()) { setError('Target required'); return }
    setError('')
    setLoading(true)
    try {
      const { id } = await api.createMission(target.trim(), mode, scope)
      navigate(`/mission/${id}`)
    } catch (e: any) {
      setError(e.message || 'Launch failed')
      setLoading(false)
    }
  }

  const selectedMode = MODES.find(m => m.id === mode)!

  return (
    <main style={{ maxWidth: '860px', margin: '0 auto', padding: '3rem 2rem' }}>
      <div style={{ marginBottom: '2.5rem' }}>
        <div style={{ fontSize: '0.65rem', letterSpacing: '0.3em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>MISSION CONTROL</div>
        <h1 style={{ fontFamily: 'var(--display)', fontSize: '2.2rem', fontWeight: 900, color: 'var(--text-bright)', marginBottom: '0.5rem' }}>Launch Mission</h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.8 }}>
          Authorized targets only. Define scope, select assessment mode, and OLYMPUS gods run in sequence.
        </p>
      </div>

      {/* Gods sequence display */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '2.5rem', flexWrap: 'wrap' }}>
        {GODS.map((g, i) => (
          <span key={g} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem', background: 'var(--accent-dim)', border: '1px solid rgba(0,229,255,0.15)', color: 'var(--accent)' }}>{g}</span>
            {i < GODS.length - 1 && <span style={{ color: 'var(--border2)', fontSize: '0.75rem' }}>→</span>}
          </span>
        ))}
      </div>

      {/* Target */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>TARGET DOMAIN / IP</label>
        <input
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="example.com"
          onKeyDown={e => e.key === 'Enter' && launch()}
          style={{ width: '100%', fontSize: '1rem', padding: '0.75rem 1rem' }}
          autoFocus
        />
      </div>

      {/* Mode */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.75rem' }}>ASSESSMENT MODE</label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1px', background: 'var(--border)' }}>
          {MODES.map(m => (
            <div
              key={m.id}
              onClick={() => setMode(m.id)}
              style={{
                padding: '1.25rem', cursor: 'pointer',
                background: mode === m.id ? 'var(--accent-dim)' : 'var(--surface)',
                borderBottom: mode === m.id ? '2px solid var(--accent)' : '2px solid transparent',
                transition: 'all 0.15s',
              }}
            >
              <div style={{ fontSize: '0.8rem', color: mode === m.id ? 'var(--accent)' : 'var(--text-bright)', marginBottom: '0.4rem', fontWeight: 700, letterSpacing: '0.1em' }}>{m.label}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: m.gates.length ? '0.6rem' : 0 }}>{m.desc}</div>
              {m.gates.length > 0 && (
                <div style={{ fontSize: '0.65rem', color: 'var(--gold)', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  {m.gates.map(g => <span key={g}>⊳ HITL gate: {g}</span>)}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Scope notes */}
      <div style={{ marginBottom: '2rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>SCOPE NOTES (optional)</label>
        <textarea
          value={scope}
          onChange={e => setScope(e.target.value)}
          placeholder="e.g. All subdomains of example.com. Exclude pay.example.com."
          rows={3}
          style={{ width: '100%', resize: 'vertical' }}
        />
      </div>

      {/* Authorization notice */}
      <div style={{
        padding: '0.9rem 1.2rem', marginBottom: '1.5rem',
        background: 'var(--accent2-dim)', border: '1px solid rgba(255,61,107,0.2)',
        fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.8,
      }}>
        ⚠ By launching this mission you confirm you have written authorization to perform security testing against the specified target. Unauthorized scanning may violate the CFAA and equivalent laws.
      </div>

      {error && <div style={{ fontSize: '0.8rem', color: 'var(--accent2)', marginBottom: '1rem' }}>✕ {error}</div>}

      <button
        onClick={launch}
        disabled={loading}
        style={{
          width: '100%', padding: '1rem',
          background: loading ? 'var(--accent-dim)' : 'var(--accent)',
          color: loading ? 'var(--accent)' : 'var(--bg)',
          fontSize: '0.85rem', letterSpacing: '0.25em',
          fontFamily: 'var(--display)', fontWeight: 900,
          border: '1px solid var(--accent)',
          cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'all 0.15s',
        }}
      >
        {loading ? '⚡ INITIALIZING...' : '⚡ LAUNCH MISSION'}
      </button>
    </main>
  )
}
