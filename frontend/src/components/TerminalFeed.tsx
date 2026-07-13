import { useEffect, useRef, useState } from 'react'
import type { LogEntry } from '../types'
import { agentMeta } from '../brand'

const LEVEL_COLOR: Record<string, string> = {
  info: 'var(--text)',
  success: 'var(--accent3)',
  warn: 'var(--gold)',
  error: 'var(--accent2)',
}

interface Props {
  logs: LogEntry[]
}

export default function TerminalFeed({ logs }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--surface)' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.75rem 1rem',
        background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      }}>
        <span className="eyebrow">Activity Log</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', color: 'var(--text-dim)', fontSize: '0.78rem' }}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
            style={{ accentColor: 'var(--accent)', width: '14px', height: '14px', cursor: 'pointer' }}
          />
          Auto-scroll
        </label>
      </div>

      <div style={{
        flex: 1, overflowY: 'auto', padding: '0.8rem 1rem',
        fontFamily: 'var(--mono)', fontSize: '0.78rem', lineHeight: 1.8,
        background: 'var(--surface)',
      }}>
        {logs.length === 0 && (
          <div style={{ color: 'var(--text-dim)', padding: '1rem 0', fontFamily: 'var(--display)' }}>
            Awaiting assessment activity...
          </div>
        )}
        {logs.map((log, i) => {
          const meta = agentMeta(log.agent)
          return (
            <div key={log.id || i} className="fade-in" style={{ display: 'grid', gridTemplateColumns: '4.8rem 7rem minmax(0, 1fr)', gap: '0.7rem', alignItems: 'flex-start', padding: '0.18rem 0' }}>
              <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap', fontSize: '0.68rem' }}>
                {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
              </span>
              <span style={{
                color: meta.tint,
                whiteSpace: 'nowrap',
                fontWeight: 800,
                fontSize: '0.7rem',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}>
                {meta.name}
              </span>
              <span style={{
                color: LEVEL_COLOR[log.level] || 'var(--text)',
                wordBreak: 'break-word',
              }}>
                {log.message}
              </span>
            </div>
          )
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
