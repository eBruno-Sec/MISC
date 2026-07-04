import { useState } from 'react'
import { api } from '../api'
import type { LiveHost } from '../types'

interface Props {
  missionId: string
  liveHosts: LiveHost[]
  onAgentRerun: (agent: string, targets?: string[]) => void
}

const STATUS_COLOR = (code: number | null) => {
  if (!code) return 'var(--text-dim)'
  if (code < 300) return 'var(--accent3)'
  if (code < 400) return 'var(--gold)'
  if (code < 500) return 'var(--accent2)'
  return 'var(--text-dim)'
}

export default function TargetsPanel({ missionId, liveHosts, onAgentRerun }: Props) {
  const [input, setInput] = useState('')
  const [runScan, setRunScan] = useState(true)
  const [adding, setAdding] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [filter, setFilter] = useState('')

  const filtered = liveHosts.filter(h =>
    !filter || h.host.toLowerCase().includes(filter.toLowerCase())
  )

  const toggle = (host: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(host) ? next.delete(host) : next.add(host)
      return next
    })
  }

  const addTargets = async () => {
    const targets = input.split(/[\n,\s]+/).map(t => t.trim()).filter(Boolean)
    if (!targets.length) return
    setAdding(true)
    try {
      await api.addTargets(missionId, targets, runScan)
      setInput('')
    } catch (e: any) {
      alert(e.message)
    } finally {
      setAdding(false)
    }
  }

  const rerunSelected = (agent: string) => {
    const targets = selected.size > 0 ? Array.from(selected) : undefined
    onAgentRerun(agent, targets)
    setSelected(new Set())
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{
        padding: '0.6rem 1rem', background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap',
      }}>
        <span style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)' }}>
          TARGETS ({liveHosts.length})
        </span>
        <input
          placeholder="filter hosts..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem', flex: 1, minWidth: '120px' }}
        />
        {selected.size > 0 && (
          <>
            <button
              onClick={() => rerunSelected('ares')}
              style={{ fontSize: '0.65rem', padding: '0.25rem 0.65rem', letterSpacing: '0.1em', cursor: 'pointer', background: 'rgba(255,61,107,0.1)', border: '1px solid var(--accent2)', color: 'var(--accent2)' }}
            >⚔ SCAN SELECTED ({selected.size})</button>
            <button
              onClick={() => setSelected(new Set())}
              style={{ fontSize: '0.65rem', color: 'var(--text-dim)', cursor: 'pointer' }}
            >clear</button>
          </>
        )}
      </div>

      {/* Host list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 && (
          <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.78rem' }}>
            No live hosts discovered yet
          </div>
        )}
        {filtered.map(h => (
          <div
            key={h.host}
            onClick={() => toggle(h.host)}
            style={{
              padding: '0.6rem 1rem',
              borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', gap: '0.75rem',
              cursor: 'pointer',
              background: selected.has(h.host) ? 'rgba(0,229,255,0.05)' : 'transparent',
              transition: 'background 0.1s',
            }}
          >
            <div style={{
              width: '14px', height: '14px', border: '1px solid var(--border2)',
              background: selected.has(h.host) ? 'var(--accent)' : 'transparent',
              flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '0.6rem', color: 'var(--bg)',
            }}>
              {selected.has(h.host) ? '✓' : ''}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-bright)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {h.host}
                {h.manually_added && <span style={{ marginLeft: '0.5rem', fontSize: '0.6rem', color: 'var(--gold)', letterSpacing: '0.1em' }}>MANUAL</span>}
              </div>
              {h.server && <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>{h.server}</div>}
            </div>
            <span style={{ fontSize: '0.7rem', color: STATUS_COLOR(h.status_code), flexShrink: 0 }}>
              {h.status_code ?? '?'}
            </span>
            <button
              onClick={e => { e.stopPropagation(); onAgentRerun('ares', [h.host]) }}
              title="Re-run Ares on this host"
              style={{
                fontSize: '0.65rem', padding: '0.15rem 0.45rem',
                border: '1px solid var(--border2)', color: 'var(--text-dim)',
                cursor: 'pointer', background: 'transparent',
                transition: 'all 0.1s', flexShrink: 0,
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent2)'; e.currentTarget.style.color = 'var(--accent2)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border2)'; e.currentTarget.style.color = 'var(--text-dim)' }}
            >⚔</button>
          </div>
        ))}
      </div>

      {/* Add target form */}
      <div style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
        <div style={{ fontSize: '0.62rem', letterSpacing: '0.15em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>ADD TARGETS</div>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="One target per line: domain.com, 10.0.0.1, *.sub.domain.com"
          rows={3}
          style={{ width: '100%', resize: 'none', fontSize: '0.78rem', marginBottom: '0.5rem' }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
            <input
              type="checkbox" checked={runScan}
              onChange={e => setRunScan(e.target.checked)}
              style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
            />
            Scan with Ares immediately
          </label>
          <button
            onClick={addTargets}
            disabled={adding || !input.trim()}
            style={{
              marginLeft: 'auto', fontSize: '0.72rem', letterSpacing: '0.15em',
              padding: '0.35rem 0.9rem',
              background: adding ? 'var(--accent-dim)' : 'var(--accent)',
              color: adding ? 'var(--accent)' : 'var(--bg)',
              border: '1px solid var(--accent)', cursor: 'pointer',
            }}
          >
            {adding ? 'ADDING...' : '+ ADD'}
          </button>
        </div>
      </div>
    </div>
  )
}
