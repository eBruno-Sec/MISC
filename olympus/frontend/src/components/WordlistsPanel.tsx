import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import type { Wordlist, WordlistCatalog } from '../types'

function fmtSize(bytes: number): string {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const CAT_COLOR: Record<string, string> = {
  content: 'var(--accent)', api: 'var(--accent)', dns: 'var(--accent3)',
  fuzz: 'var(--accent2)', auth: 'var(--gold)', generated: 'var(--accent3)',
}

function Row({ wl, onPreview, previewing, preview }: {
  wl: Wordlist
  onPreview: (id: string) => void
  previewing: string | null
  preview: Record<string, string>
}) {
  const color = CAT_COLOR[wl.category] || 'var(--text-dim)'
  const open = previewing === wl.id
  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.7rem 0.25rem' }}>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: wl.exists ? color : 'var(--border2)', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-bright)' }}>{wl.name}</span>
            <span style={{ fontSize: '0.58rem', letterSpacing: '0.12em', padding: '0.1rem 0.4rem', border: `1px solid ${color}`, color, textTransform: 'uppercase' }}>{wl.category}</span>
            {wl.kind === 'generated' && (
              <span style={{ fontSize: '0.58rem', letterSpacing: '0.12em', padding: '0.1rem 0.4rem', border: '1px solid var(--accent3)', color: 'var(--accent3)' }}>GENERATED</span>
            )}
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>{wl.desc}</div>
        </div>
        <div style={{ textAlign: 'right', fontSize: '0.68rem', color: 'var(--text-dim)', flexShrink: 0, minWidth: 90 }}>
          {wl.exists
            ? <>{wl.count.toLocaleString()} lines<br /><span style={{ opacity: 0.7 }}>{fmtSize(wl.size)}</span></>
            : <span style={{ color: 'var(--accent2)' }}>not present</span>}
        </div>
        {wl.exists && (
          <div style={{ display: 'flex', gap: '0.35rem', flexShrink: 0 }}>
            <button onClick={() => onPreview(wl.id)}
              style={{ fontSize: '0.6rem', letterSpacing: '0.1em', padding: '0.2rem 0.55rem', border: '1px solid var(--border2)', color: 'var(--text-dim)' }}>
              {open ? 'HIDE' : 'PEEK'}
            </button>
            <a href={api.wordlistDownloadUrl(wl.id)} download
              style={{ fontSize: '0.6rem', letterSpacing: '0.1em', padding: '0.2rem 0.55rem', border: '1px solid var(--accent)', color: 'var(--accent)', textDecoration: 'none' }}>
              GET
            </a>
          </div>
        )}
      </div>
      {open && (
        <pre style={{
          background: 'var(--bg)', border: '1px solid var(--border2)', margin: '0 0 0.7rem',
          padding: '0.7rem', fontSize: '0.72rem', lineHeight: 1.5, color: 'var(--accent3)',
          maxHeight: 220, overflow: 'auto', whiteSpace: 'pre',
        }}>{preview[wl.id] ?? 'loading...'}</pre>
      )}
    </div>
  )
}

export default function WordlistsPanel({ missionId }: { missionId: string }) {
  const [cat, setCat] = useState<WordlistCatalog | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [generating, setGenerating] = useState(false)
  const [previewing, setPreviewing] = useState<string | null>(null)
  const [preview, setPreview] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    try {
      setCat(await api.listWordlists())
    } catch (e: any) {
      setError(e.message || 'Failed to load wordlists')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const onPreview = async (id: string) => {
    if (previewing === id) { setPreviewing(null); return }
    setPreviewing(id)
    if (!preview[id]) {
      try {
        const text = await api.previewWordlist(id, 60)
        setPreview(p => ({ ...p, [id]: text || '(empty)' }))
      } catch {
        setPreview(p => ({ ...p, [id]: '(preview failed)' }))
      }
    }
  }

  const generate = async () => {
    setGenerating(true); setError('')
    try {
      await api.generateWordlist(missionId)
      await load()
    } catch (e: any) {
      setError(e.message || 'Generation failed')
    } finally {
      setGenerating(false)
    }
  }

  if (loading) return <div style={{ padding: '1.5rem', fontSize: '0.8rem', color: 'var(--text-dim)' }}>Loading wordlists...</div>

  const curated = cat?.wordlists.filter(w => w.kind === 'curated') ?? []
  const generated = cat?.wordlists.filter(w => w.kind === 'generated') ?? []

  return (
    <div style={{ padding: '0.5rem 1rem 1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 0', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
          {cat?.available ?? 0} of {cat?.total ?? 0} available · defaults: {cat?.default_content_ids.join(', ')}
        </div>
        <button onClick={generate} disabled={generating}
          style={{
            fontSize: '0.68rem', letterSpacing: '0.15em', padding: '0.45rem 1rem',
            border: '1px solid var(--accent3)', color: 'var(--accent3)',
            background: 'var(--accent3-dim)', cursor: generating ? 'not-allowed' : 'pointer',
          }}>
          {generating ? 'FORGING...' : '⚙ GENERATE FROM RECON'}
        </button>
      </div>

      {error && <div style={{ fontSize: '0.78rem', color: 'var(--accent2)', margin: '0.5rem 0' }}>{error}</div>}

      {generated.length > 0 && (
        <>
          <div style={{ fontSize: '0.6rem', letterSpacing: '0.22em', color: 'var(--accent3)', margin: '1rem 0 0.4rem' }}>
            TARGET-SPECIFIC ({generated.length})
          </div>
          {generated.map(wl => (
            <Row key={wl.id} wl={wl} onPreview={onPreview} previewing={previewing} preview={preview} />
          ))}
        </>
      )}

      <div style={{ fontSize: '0.6rem', letterSpacing: '0.22em', color: 'var(--accent)', margin: '1.25rem 0 0.4rem' }}>
        CURATED ({curated.length})
      </div>
      {curated.map(wl => (
        <Row key={wl.id} wl={wl} onPreview={onPreview} previewing={previewing} preview={preview} />
      ))}

      <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '1.25rem', lineHeight: 1.7 }}>
        ARES uses the generated target list plus your selected curated lists for content discovery.
        Select which curated lists to run when you launch a mission.
      </div>
    </div>
  )
}
