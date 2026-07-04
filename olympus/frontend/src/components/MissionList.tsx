import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionSummary, MissionStatus } from '../types'

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--text-dim)',
  planning: 'var(--accent)',
  recon: 'var(--accent)',
  scanning: 'var(--gold)',
  exploiting: 'var(--accent2)',
  post_exploit: 'var(--accent2)',
  reporting: 'var(--accent3)',
  complete: 'var(--accent3)',
  awaiting_approval: 'var(--gold)',
  failed: 'var(--crit)',
}

const MODE_LABEL: Record<string, string> = {
  passive: 'PASSIVE',
  active: 'ACTIVE',
  full: 'FULL',
}

export default function MissionList() {
  const [missions, setMissions] = useState<MissionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = () =>
    api.listMissions()
      .then(setMissions)
      .finally(() => setLoading(false))

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const del = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    if (!confirm('Delete this mission?')) return
    await api.deleteMission(id)
    setMissions(m => m.filter(x => x.id !== id))
  }

  return (
    <main style={{ maxWidth: '1200px', margin: '0 auto', padding: '2.5rem 2rem' }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '2rem' }}>
        <div>
          <div style={{ fontSize: '0.65rem', letterSpacing: '0.3em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>MISSION ARCHIVE</div>
          <h1 style={{ fontFamily: 'var(--display)', fontSize: '2rem', fontWeight: 900, color: 'var(--text-bright)' }}>All Missions</h1>
        </div>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>{missions.length} total</span>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
          Loading...
        </div>
      )}

      {!loading && missions.length === 0 && (
        <div style={{
          border: '1px dashed var(--border2)', padding: '5rem 2rem',
          textAlign: 'center', color: 'var(--text-dim)',
        }}>
          <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>⚡</div>
          <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--text)' }}>No missions launched</div>
          <div style={{ fontSize: '0.75rem' }}>Click <strong style={{ color: 'var(--accent)' }}>+ NEW MISSION</strong> to begin</div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1px', background: 'var(--border)' }}>
        {missions.map((m) => (
          <div
            key={m.id}
            onClick={() => navigate(`/mission/${m.id}`)}
            style={{
              background: 'var(--surface)', padding: '1.1rem 1.5rem',
              display: 'grid', gridTemplateColumns: '1fr auto auto auto',
              alignItems: 'center', gap: '1.5rem',
              cursor: 'pointer', transition: 'background 0.1s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'var(--surface)')}
          >
            <div>
              <div style={{ fontSize: '0.95rem', color: 'var(--text-bright)', marginBottom: '0.25rem' }}>{m.target}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                {new Date(m.created_at).toLocaleString()} · {m.id.slice(0, 8).toUpperCase()}
              </div>
            </div>
            <span style={{
              fontSize: '0.65rem', letterSpacing: '0.15em', padding: '0.2rem 0.6rem',
              border: '1px solid var(--border2)', color: 'var(--text-dim)',
            }}>
              {MODE_LABEL[m.mode] || m.mode}
            </span>
            <span style={{
              fontSize: '0.7rem', letterSpacing: '0.1em',
              color: STATUS_COLOR[m.status] || 'var(--text-dim)',
              display: 'flex', alignItems: 'center', gap: '0.4rem',
            }}>
              {['recon','scanning','exploiting','planning','reporting'].includes(m.status) && (
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'currentColor', animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />
              )}
              {m.status.toUpperCase().replace('_', ' ')}
            </span>
            <button
              onClick={(e) => del(e, m.id)}
              style={{ fontSize: '0.75rem', color: 'var(--text-dim)', padding: '0.25rem 0.5rem' }}
              title="Delete"
            >✕</button>
          </div>
        ))}
      </div>
    </main>
  )
}
