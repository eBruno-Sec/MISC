import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionSummary, Severity } from '../types'

// Client-side schema check mirrors core/backup.validate_backup so a bad file is
// caught before any upload. Returns a reason string, or null when the shape is OK.
function validateBackupShape(data: any): string | null {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'not a JSON object'
  if (String(data.version) !== '1') return 'unsupported or missing version'
  if (!data.mission || typeof data.mission !== 'object') return 'missing mission record'
  const target = typeof data.mission.target === 'string' ? data.mission.target.trim() : ''
  if (!target) return 'missing target'
  const findings = data.findings ?? data.mission.findings
  if (findings !== undefined && findings !== null && !Array.isArray(findings)) return 'malformed findings'
  return null
}

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

// Severity peek order + colors (matches report + finding panel palette).
const SEV_META: { key: Severity; label: string; color: string }[] = [
  { key: 'critical', label: 'C', color: 'var(--crit)' },
  { key: 'high', label: 'H', color: 'var(--high)' },
  { key: 'medium', label: 'M', color: 'var(--med)' },
  { key: 'low', label: 'L', color: 'var(--low)' },
  { key: 'info', label: 'I', color: 'var(--info)' },
]

const FAV_KEY = 'yggdrasil_favorites'

function loadFavorites(): string[] {
  try {
    const raw = localStorage.getItem(FAV_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
  } catch {
    return []
  }
}

// Inline severity "peek": one small chip per severity, lit when count > 0.
function SeverityPeek({ counts }: { counts?: Partial<Record<Severity, number>> }) {
  const c: Partial<Record<Severity, number>> = counts ?? {}
  const total = SEV_META.reduce((n, s) => n + (c[s.key] ?? 0), 0)
  if (total === 0) {
    return <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>no findings yet</span>
  }
  return (
    <div style={{ display: 'flex', gap: '0.3rem', alignItems: 'center', flexWrap: 'wrap' }}>
      {SEV_META.map(s => {
        const n = c[s.key] ?? 0
        return (
          <span
            key={s.key}
            title={`${s.key}: ${n}`}
            style={{
              fontSize: '0.72rem', fontFamily: 'var(--mono)', letterSpacing: '0.03em',
              padding: '0.1rem 0.4rem', minWidth: '28px', textAlign: 'center',
              border: `1px solid ${n ? s.color : 'var(--border2)'}`,
              color: n ? s.color : 'var(--text-dim)',
              opacity: n ? 1 : 0.45,
            }}
          >
            {s.label} {n}
          </span>
        )
      })}
    </div>
  )
}

export default function MissionList() {
  const [missions, setMissions] = useState<MissionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const [relaunching, setRelaunching] = useState<string | null>(null)
  const [favorites, setFavorites] = useState<string[]>(loadFavorites)
  const [query, setQuery] = useState('')
  const [importErr, setImportErr] = useState<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  // Read a .json backup, validate client-side, then hydrate via the server (which
  // re-validates and imports as a new mission). Any failure -> one clear banner.
  const handleFile = async (file: File) => {
    setImportErr(null)
    setImporting(true)
    try {
      const text = await file.text()
      let data: unknown = null
      try { data = JSON.parse(text) } catch { throw new Error('parse') }
      const problem = validateBackupShape(data)
      if (problem) throw new Error(problem)
      const res = await api.restoreSession(data)
      navigate(`/mission/${res.id}`)
    } catch {
      setImportErr('Invalid or corrupted progress file')
    } finally {
      setImporting(false)
    }
  }

  const relaunch = async (e: React.MouseEvent, m: MissionSummary) => {
    e.stopPropagation()
    if (relaunching) return
    setRelaunching(m.id)
    try {
      const res = await api.relaunchMission(m.id)
      navigate(`/mission/${res.id}`)
    } catch (err) {
      alert('Relaunch failed: ' + (err as Error).message)
      setRelaunching(null)
    }
  }

  const load = () =>    api.listMissions()
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
    setFavorites(prev => {
      const next = prev.filter(x => x !== id)
      try { localStorage.setItem(FAV_KEY, JSON.stringify(next)) } catch { /* ignore quota */ }
      return next
    })
  }

  const toggleFav = (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    setFavorites(prev => {
      const next = prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
      try { localStorage.setItem(FAV_KEY, JSON.stringify(next)) } catch { /* ignore quota */ }
      return next
    })
  }

  const favSet = new Set(favorites)
  const q = query.trim().toLowerCase()
  const visible = missions
    .filter(m => !q || m.target.toLowerCase().includes(q) || m.id.toLowerCase().includes(q))
    // favorites pinned to the top; sort is stable so the API's created_at order holds otherwise
    .sort((a, b) => (favSet.has(b.id) ? 1 : 0) - (favSet.has(a.id) ? 1 : 0))

  return (
    <main style={{ maxWidth: '1200px', margin: '0 auto', padding: '2.5rem 2rem' }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '1.5rem', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: '0.7rem', letterSpacing: '0.3em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>MISSION ARCHIVE</div>
          <h1 style={{ fontFamily: 'var(--display)', fontSize: '2rem', fontWeight: 900, color: 'var(--text-bright)' }}>All Missions</h1>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>
          {q ? `${visible.length} / ${missions.length}` : `${missions.length} total`}
          {favorites.length > 0 && <span style={{ color: 'var(--gold)' }}> · ★ {favorites.length}</span>}
        </span>
      </div>

      <input
        value={query}
        onChange={e => setQuery(e.target.value)}
        placeholder="filter missions by target or id..."
        style={{ width: '100%', marginBottom: '0.75rem', fontSize: '0.85rem' }}
      />

      {/* Restore a saved session. Drag-and-drop target + file picker (spec: State
          Hydration). Validated client-side, then re-validated + imported server-side. */}
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault(); setDragOver(false)
          const f = e.dataTransfer.files?.[0]
          if (f) handleFile(f)
        }}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem',
          flexWrap: 'wrap', marginBottom: '1.25rem',
          padding: '0.75rem 1rem',
          border: `1px dashed ${dragOver ? 'var(--accent)' : 'var(--border2)'}`,
          background: dragOver ? 'var(--accent-dim)' : 'transparent',
          transition: 'all 0.12s',
        }}
      >
        <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
          {importing
            ? 'Restoring session…'
            : dragOver
              ? 'Drop the .json backup to restore'
              : 'Restore a saved session — drag a backup here, or'}
        </span>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          style={{ display: 'none' }}
          onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = '' }}
        />
        <button
          onClick={() => fileRef.current?.click()}
          disabled={importing}
          aria-label="Upload progress backup file"
          className="touch-target"
          style={{
            fontSize: '0.72rem', letterSpacing: '0.12em', padding: '0.4rem 0.9rem',
            border: '1px solid var(--accent)', color: 'var(--accent)', background: 'var(--accent-dim)',
            cursor: importing ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap',
          }}
        >↑ UPLOAD PROGRESS (.json)</button>
      </div>

      {importErr && (
        <div role="alert" style={{
          marginBottom: '1.25rem', padding: '0.7rem 1rem',
          border: '1px solid var(--crit)', borderLeft: '4px solid var(--crit)',
          background: 'rgba(255,0,64,0.08)', color: 'var(--crit)',
          fontSize: '0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem',
        }}>
          <span>⚠ {importErr}</span>
          <button
            onClick={() => setImportErr(null)}
            aria-label="Dismiss error"
            style={{ color: 'var(--crit)', fontSize: '0.9rem', padding: '0.1rem 0.4rem', cursor: 'pointer' }}
          >✕</button>
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
          Loading...
        </div>
      )}

      {!loading && missions.length === 0 && (
        <div style={{
          border: '1px dashed var(--border2)', padding: '5rem 2rem',
          textAlign: 'center', color: 'var(--text-dim)',
        }}>
          <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>⚡</div>
          <div style={{ fontSize: '0.9rem', marginBottom: '0.5rem', color: 'var(--text)' }}>No missions launched</div>
          <div style={{ fontSize: '0.8rem' }}>Click <strong style={{ color: 'var(--accent)' }}>+ NEW MISSION</strong> to begin</div>
        </div>
      )}

      {!loading && missions.length > 0 && visible.length === 0 && (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
          No missions match “{query}”.
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1px', background: 'var(--border)' }}>
        {visible.map((m) => (
          <div
            key={m.id}
            onClick={() => navigate(`/mission/${m.id}`)}
            style={{
              background: 'var(--surface)', padding: '1.1rem 1.5rem',
              display: 'grid', gridTemplateColumns: 'auto 1fr auto auto auto auto',
              alignItems: 'center', gap: '1.25rem',
              cursor: 'pointer', transition: 'background 0.1s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'var(--surface)')}
          >
            <button
              onClick={(e) => toggleFav(e, m.id)}
              title={favSet.has(m.id) ? 'Unfavorite' : 'Favorite'}
              style={{
                fontSize: '1.1rem', lineHeight: 1, padding: '0.15rem',
                color: favSet.has(m.id) ? 'var(--gold)' : 'var(--text-dim)',
              }}
            >{favSet.has(m.id) ? '★' : '☆'}</button>

            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: '1rem', color: 'var(--text-bright)', marginBottom: '0.25rem', wordBreak: 'break-all' }}>{m.target}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
                {new Date(m.created_at).toLocaleString()} · {m.id.slice(0, 8).toUpperCase()}
              </div>
              <SeverityPeek counts={m.severity_counts} />
            </div>

            <span style={{
              fontSize: '0.7rem', letterSpacing: '0.15em', padding: '0.2rem 0.6rem',
              border: '1px solid var(--border2)', color: 'var(--text-dim)',
            }}>
              {MODE_LABEL[m.mode] || m.mode}
            </span>
            <span style={{
              fontSize: '0.75rem', letterSpacing: '0.1em',
              color: STATUS_COLOR[m.status] || 'var(--text-dim)',
              display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap',
            }}>
              {['recon','scanning','exploiting','planning','reporting'].includes(m.status) && (
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'currentColor', animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />
              )}
              {m.status.toUpperCase().replace('_', ' ')}
            </span>
            <button
              onClick={(e) => relaunch(e, m)}
              disabled={relaunching === m.id}
              style={{
                fontSize: '0.72rem', letterSpacing: '0.12em', padding: '0.3rem 0.75rem',
                border: '1px solid var(--accent)', color: 'var(--accent)',
                background: 'var(--accent-dim)',
                cursor: relaunching === m.id ? 'not-allowed' : 'pointer',
                whiteSpace: 'nowrap',
              }}
              title="Relaunch as a new mission with the same target, mode, and scope"
            >{relaunching === m.id ? '...' : '↻ RELAUNCH'}</button>
            <button
              onClick={(e) => del(e, m.id)}
              style={{ fontSize: '0.8rem', color: 'var(--text-dim)', padding: '0.25rem 0.5rem' }}
              title="Delete"
            >✕</button>
          </div>
        ))}
      </div>
    </main>
  )
}
