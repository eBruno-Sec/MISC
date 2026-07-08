import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import type { SurfaceInventory } from '../types'

// Read-only attack-surface inventory: deduped endpoints + params discovered by
// ARES (crawl + archives + parameter mining). COPY yields the example URL to
// paste into the request workbench (/replay, /fuzz) or curl.
export default function SurfacePanel({ missionId }: { missionId: string }) {
  const [inv, setInv] = useState<SurfaceInventory | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [q, setQ] = useState('')

  const load = useCallback(async () => {
    try {
      setInv(await api.getSurface(missionId))
    } catch (e: any) {
      setError(e.message || 'Failed to load attack surface')
    } finally {
      setLoading(false)
    }
  }, [missionId])

  useEffect(() => { load() }, [load])

  if (loading) return <div style={{ padding: '1.5rem', fontSize: '0.8rem', color: 'var(--text-dim)' }}>Loading attack surface...</div>

  const endpoints = inv?.endpoints ?? []
  const cov = inv?.coverage
  const needle = q.trim().toLowerCase()
  const filtered = needle
    ? endpoints.filter(e => (e.path + ' ' + e.params.join(' ') + ' ' + e.host).toLowerCase().includes(needle))
    : endpoints

  const stat = (label: string, value: number | undefined) => (
    <div style={{ textAlign: 'center', padding: '0.5rem 0.75rem', border: '1px solid var(--border)', minWidth: 82 }}>
      <div style={{ fontSize: '1.2rem', fontWeight: 900, color: 'var(--accent)', fontFamily: 'var(--display)' }}>{value ?? 0}</div>
      <div style={{ fontSize: '0.55rem', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{label}</div>
    </div>
  )

  return (
    <div style={{ padding: '0.5rem 1rem 1.5rem', overflow: 'auto' }}>
      {error && <div style={{ fontSize: '0.78rem', color: 'var(--accent2)', margin: '0.5rem 0' }}>{error}</div>}

      {endpoints.length === 0 && !error && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '1rem 0', lineHeight: 1.7 }}>
          No attack surface recorded yet. It is captured when ARES runs its offensive pass
          (crawl + archives + parameter mining) during an active or full mission.
        </div>
      )}

      {endpoints.length > 0 && (
        <>
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', margin: '0.75rem 0' }}>
            {stat('Endpoints', inv?.total)}
            {stat('Parameterized', inv?.parameterized)}
            {stat('URLs crawled', cov?.crawled_urls)}
            {stat('Content paths', cov?.content_paths)}
            {stat('Hosts scanned', cov?.hosts_scanned)}
            {stat('Subdomains', cov?.subdomains)}
            {(cov?.network_hosts ?? 0) > 0 && stat('Network hosts', cov?.network_hosts)}
          </div>

          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="filter by path / param / host..."
            style={{
              width: '100%', padding: '0.5rem 0.7rem', margin: '0.5rem 0 0.5rem',
              background: 'var(--bg)', border: '1px solid var(--border2)', color: 'var(--text-bright)',
              fontSize: '0.78rem', fontFamily: 'var(--mono)',
            }}
          />

          <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--text-dim)', margin: '0.25rem 0 0.5rem' }}>
            {filtered.length} SHOWN
          </div>

          {filtered.map((e, i) => (
            <div key={i} style={{ borderBottom: '1px solid var(--border)', padding: '0.55rem 0.25rem', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-bright)', fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>
                  {e.path}
                  {e.parameterized && (
                    <span style={{ fontSize: '0.55rem', letterSpacing: '0.1em', color: 'var(--gold)', marginLeft: '0.5rem' }}>PARAM</span>
                  )}
                </div>
                <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginTop: '0.15rem', wordBreak: 'break-all' }}>
                  {e.host}{e.params.length > 0 ? ` · ${e.params.join(', ')}` : ''}
                </div>
              </div>
              <button
                onClick={() => { void navigator.clipboard?.writeText(e.example) }}
                title="Copy example URL — paste into the workbench (/replay, /fuzz) or curl"
                style={{ fontSize: '0.6rem', letterSpacing: '0.1em', padding: '0.2rem 0.55rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', flexShrink: 0, cursor: 'pointer', background: 'transparent' }}>
                COPY
              </button>
            </div>
          ))}
        </>
      )}
    </div>
  )
}
