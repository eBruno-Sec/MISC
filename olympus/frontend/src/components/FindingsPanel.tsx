import { useState } from 'react'
import type { Finding, Severity } from '../types'

const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  info: 'var(--info)',
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  findings: Finding[]
}

export default function FindingsPanel({ findings }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [filter, setFilter] = useState<Severity | 'all'>('all')

  const toggle = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const stats = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length
    return acc
  }, {} as Record<Severity, number>)

  const visible = filter === 'all' ? findings : findings.filter(f => f.severity === filter)
  const sorted = [...visible].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '0.6rem 1rem',
        background: 'var(--surface)', borderBottom: '1px solid var(--border)',
        fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)',
      }}>
        FINDINGS ({findings.length})
      </div>

      {/* Severity pills */}
      <div style={{
        display: 'flex', gap: '1px', background: 'var(--border)',
        borderBottom: '1px solid var(--border)',
      }}>
        <button
          onClick={() => setFilter('all')}
          style={{
            flex: 1, padding: '0.5rem', fontSize: '0.65rem', letterSpacing: '0.1em',
            background: filter === 'all' ? 'var(--surface2)' : 'var(--surface)',
            color: filter === 'all' ? 'var(--text-bright)' : 'var(--text-dim)',
            transition: 'all 0.1s',
          }}
        >ALL {findings.length}</button>
        {SEV_ORDER.map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            style={{
              flex: 1, padding: '0.5rem', fontSize: '0.65rem', letterSpacing: '0.05em',
              background: filter === s ? `${SEV_COLOR[s]}18` : 'var(--surface)',
              color: stats[s] > 0 ? SEV_COLOR[s] : 'var(--border2)',
              borderBottom: filter === s ? `2px solid ${SEV_COLOR[s]}` : '2px solid transparent',
              transition: 'all 0.1s',
            }}
          >{s.slice(0, 4).toUpperCase()} {stats[s]}</button>
        ))}
      </div>

      {/* Findings list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {sorted.length === 0 && (
          <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.78rem' }}>
            No findings yet
          </div>
        )}
        {sorted.map(f => (
          <div key={f.id} style={{ borderBottom: '1px solid var(--border)' }}>
            <div
              onClick={() => toggle(f.id)}
              style={{
                padding: '0.75rem 1rem', cursor: 'pointer',
                display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
                background: expanded.has(f.id) ? 'var(--surface2)' : 'transparent',
                transition: 'background 0.1s',
              }}
            >
              <span style={{
                fontSize: '0.58rem', padding: '0.15rem 0.4rem', whiteSpace: 'nowrap', flexShrink: 0, marginTop: '1px',
                background: `${SEV_COLOR[f.severity]}15`,
                border: `1px solid ${SEV_COLOR[f.severity]}40`,
                color: SEV_COLOR[f.severity],
                letterSpacing: '0.1em',
              }}>
                {f.severity.toUpperCase()}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-bright)', lineHeight: 1.4, wordBreak: 'break-word' }}>
                  {f.title}
                </div>
                {!expanded.has(f.id) && f.description && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.description}
                  </div>
                )}
              </div>
              <span style={{ color: 'var(--text-dim)', flexShrink: 0, fontSize: '0.75rem' }}>
                {expanded.has(f.id) ? '▲' : '▼'}
              </span>
            </div>

            {expanded.has(f.id) && (
              <div style={{ padding: '0.75rem 1rem 1rem 1rem', background: 'var(--surface)', borderTop: '1px solid var(--border)' }}>
                {f.cvss_score != null && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--gold)', marginBottom: '0.75rem' }}>CVSS {f.cvss_score.toFixed(1)}</div>
                )}
                {f.description && (
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent)', marginBottom: '0.3rem' }}>DESCRIPTION</div>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text)', lineHeight: 1.8 }}>{f.description}</p>
                  </div>
                )}
                {f.evidence && (
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent)', marginBottom: '0.3rem' }}>EVIDENCE</div>
                    <pre style={{ fontSize: '0.72rem', color: 'var(--accent3)', background: 'var(--surface2)', padding: '0.6rem', lineHeight: 1.7, overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>{f.evidence}</pre>
                  </div>
                )}
                {f.remediation && (
                  <div>
                    <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent)', marginBottom: '0.3rem' }}>REMEDIATION</div>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text)', lineHeight: 1.8 }}>{f.remediation}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
