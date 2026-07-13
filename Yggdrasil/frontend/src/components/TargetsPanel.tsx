import { useState } from 'react'
import { api } from '../api'
import type { LiveHost } from '../types'
import { agentMeta } from '../brand'

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
  const tyr = agentMeta('ares')

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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: 'var(--surface)' }}>
      <div style={{
        padding: '0.75rem 1rem',
        background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        flexWrap: 'wrap',
      }}>
        <span className="eyebrow">Targets ({liveHosts.length})</span>
        <input
          placeholder="Filter hosts..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ fontSize: '0.82rem', padding: '0.42rem 0.65rem', flex: 1, minWidth: '140px' }}
        />
        {selected.size > 0 && (
          <>
            <button
              onClick={() => rerunSelected('ares')}
              style={{
                fontSize: '0.78rem',
                padding: '0.42rem 0.7rem',
                cursor: 'pointer',
                background: 'var(--accent2-dim)',
                border: '1px solid var(--accent2)',
                color: 'var(--accent2)',
                fontWeight: 750,
              }}
            >Run {tyr.name} ({selected.size})</button>
            <button
              onClick={() => setSelected(new Set())}
              style={{ fontSize: '0.78rem', color: 'var(--text-dim)', cursor: 'pointer' }}
            >Clear</button>
          </>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 && (
          <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.86rem' }}>
            No live hosts discovered yet
          </div>
        )}
        {filtered.map(h => (
          <div
            key={h.host}
            onClick={() => toggle(h.host)}
            style={{
              padding: '0.75rem 1rem',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              cursor: 'pointer',
              background: selected.has(h.host) ? 'var(--accent-dim)' : 'transparent',
              transition: 'background 0.1s',
            }}
          >
            <div style={{
              width: '16px',
              height: '16px',
              border: '1px solid var(--border2)',
              borderRadius: '4px',
              background: selected.has(h.host) ? 'var(--accent)' : 'var(--surface)',
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.65rem',
              color: '#fff',
            }}>
              {selected.has(h.host) ? 'X' : ''}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-bright)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 700 }}>
                {h.host}
                {h.manually_added && <span style={{ marginLeft: '0.5rem', fontSize: '0.72rem', color: 'var(--gold)' }}>manual</span>}
              </div>
              {h.server && <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>{h.server}</div>}
            </div>
            <span style={{ fontSize: '0.78rem', color: STATUS_COLOR(h.status_code), flexShrink: 0, fontWeight: 750 }}>
              {h.status_code ?? '?'}
            </span>
            <button
              onClick={e => { e.stopPropagation(); onAgentRerun('ares', [h.host]) }}
              title={`Re-run ${tyr.name} on this host`}
              style={{
                fontSize: '0.76rem',
                padding: '0.28rem 0.55rem',
                border: '1px solid var(--border2)',
                color: 'var(--text-dim)',
                cursor: 'pointer',
                background: 'var(--surface)',
                flexShrink: 0,
                fontWeight: 750,
              }}
            >Run</button>
          </div>
        ))}
      </div>

      <div style={{ padding: '0.85rem 1rem', borderTop: '1px solid var(--border)', background: 'var(--surface2)' }}>
        <div className="eyebrow" style={{ marginBottom: '0.5rem' }}>Add Targets</div>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="One target per line: domain.com, 10.0.0.1, *.sub.domain.com"
          rows={3}
          style={{ width: '100%', resize: 'none', fontSize: '0.82rem', marginBottom: '0.6rem' }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', fontSize: '0.82rem', color: 'var(--text-dim)' }}>
            <input
              type="checkbox" checked={runScan}
              onChange={e => setRunScan(e.target.checked)}
              style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
            />
            Run {tyr.name} immediately
          </label>
          <button
            onClick={addTargets}
            disabled={adding || !input.trim()}
            style={{
              marginLeft: 'auto',
              fontSize: '0.82rem',
              padding: '0.45rem 0.85rem',
              background: adding ? 'var(--accent-dim)' : 'var(--accent)',
              color: adding ? 'var(--accent)' : '#fff',
              border: '1px solid var(--accent)',
              fontWeight: 800,
            }}
          >
            {adding ? 'Adding...' : 'Add Targets'}
          </button>
        </div>
      </div>
    </div>
  )
}
