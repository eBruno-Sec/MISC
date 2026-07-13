import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionSummary } from '../types'

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
  passive: 'Passive',
  active: 'Active',
  full: 'Full',
}

export default function MissionList() {
  const [missions, setMissions] = useState<MissionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [relaunchingId, setRelaunchingId] = useState<string | null>(null)
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
    if (!confirm('Delete this assessment?')) return
    await api.deleteMission(id)
    setMissions(m => m.filter(x => x.id !== id))
  }

  const relaunch = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    setRelaunchingId(id)
    try {
      const mission = await api.relaunchMission(id)
      await load()
      navigate(`/mission/${mission.id}`)
    } catch (err: any) {
      alert(err?.message || 'Relaunch failed')
    } finally {
      setRelaunchingId(null)
    }
  }

  return (
    <main style={{ maxWidth: '1180px', margin: '0 auto', padding: '2.75rem 1.25rem 4rem' }}>
      <section style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: '1rem', marginBottom: '1.6rem', flexWrap: 'wrap' }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: '0.55rem' }}>Assessment Archive</div>
          <h1 style={{ fontSize: '2.1rem', fontWeight: 850, color: 'var(--text-bright)', lineHeight: 1.1 }}>All Assessments</h1>
        </div>
        <span style={{
          fontSize: '0.82rem',
          color: 'var(--text-dim)',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: '999px',
          padding: '0.35rem 0.75rem',
        }}>{missions.length} total</span>
      </section>

      {loading && (
        <div className="soft-panel" style={{ textAlign: 'center', padding: '4rem 2rem', color: 'var(--text-dim)', fontSize: '0.9rem' }}>
          Loading assessments...
        </div>
      )}

      {!loading && missions.length === 0 && (
        <div className="soft-panel" style={{ padding: '4.5rem 2rem', textAlign: 'center', color: 'var(--text-dim)' }}>
          <div style={{ fontSize: '1rem', marginBottom: '0.4rem', color: 'var(--text-bright)', fontWeight: 800 }}>No assessments yet</div>
          <div style={{ fontSize: '0.88rem' }}>Start a new assessment when you are ready.</div>
        </div>
      )}

      {!loading && missions.length > 0 && (
        <div className="soft-panel" style={{ overflow: 'hidden' }}>
          {missions.map((m, index) => {
            const color = STATUS_COLOR[m.status] || 'var(--text-dim)'
            const isLive = !['complete', 'failed'].includes(m.status)
            return (
              <div
                key={m.id}
                onClick={() => navigate(`/mission/${m.id}`)}
                style={{
                  padding: '1rem 1.15rem',
                  display: 'grid',
                  gridTemplateColumns: 'minmax(220px, 1fr) auto auto auto auto',
                  alignItems: 'center',
                  gap: '0.9rem',
                  cursor: 'pointer',
                  transition: 'background 0.15s',
                  borderTop: index === 0 ? 'none' : '1px solid var(--border)',
                  background: 'var(--surface)',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'var(--surface)')}
              >
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: '0.98rem', color: 'var(--text-bright)', marginBottom: '0.25rem', fontWeight: 750, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.target}
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>
                    {new Date(m.created_at).toLocaleString()} - {m.id.slice(0, 8).toUpperCase()}
                  </div>
                </div>
                <span style={{
                  fontSize: '0.78rem',
                  padding: '0.28rem 0.62rem',
                  border: '1px solid var(--border)',
                  borderRadius: '999px',
                  color: 'var(--text)',
                  background: 'var(--surface2)',
                  whiteSpace: 'nowrap',
                }}>
                  {MODE_LABEL[m.mode] || m.mode}
                </span>
                <span style={{
                  fontSize: '0.78rem',
                  color,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  fontWeight: 750,
                  whiteSpace: 'nowrap',
                }}>
                  {isLive && (
                    <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />
                  )}
                  {m.status.replace('_', ' ')}
                </span>
                <button
                  onClick={(e) => relaunch(e, m.id)}
                  disabled={relaunchingId === m.id}
                  style={{
                    fontSize: '0.78rem',
                    color: 'var(--accent)',
                    border: '1px solid var(--border2)',
                    background: 'var(--surface)',
                    padding: '0.42rem 0.72rem',
                    whiteSpace: 'nowrap',
                    fontWeight: 750,
                  }}
                  title="Start a fresh assessment with the same target, mode, and scope"
                >
                  {relaunchingId === m.id ? 'Starting...' : 'Relaunch'}
                </button>
                <button
                  onClick={(e) => del(e, m.id)}
                  style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '0.38rem 0.58rem', border: '1px solid transparent' }}
                  title="Delete"
                >
                  Delete
                </button>
              </div>
            )
          })}
        </div>
      )}
    </main>
  )
}
