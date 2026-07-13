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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.6rem 1rem',
        background: 'var(--surface)', borderBottom: '1px solid var(--border)',
        fontSize: '0.65rem', letterSpacing: '0.2em',
      }}>
        <span style={{ color: 'var(--text-dim)' }}>MISSION LOG</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', color: 'var(--text-dim)' }}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
            style={{ accentColor: 'var(--accent)', width: '12px', height: '12px', cursor: 'pointer' }}
          />
          AUTOSCROLL
        </label>
      </div>

      <div style={{
        flex: 1, overflowY: 'auto', padding: '0.75rem 1rem',
        fontFamily: 'var(--mono)', fontSize: '0.78rem', lineHeight: 1.9,
        background: 'var(--bg)',
      }}>
        {logs.length === 0 && (
          <div style={{ color: 'var(--text-dim)', padding: '1rem 0' }}>
            <span style={{ animation: 'blink 1s ease infinite', display: 'inline-block' }}>█</span> Awaiting mission start...
          </div>
        )}
        {logs.map((log, i) => (
          <div key={log.id || i} className="fade-in" style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
            <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap', flexShrink: 0, fontSize: '0.68rem' }}>
              {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
            </span>
            <span style={{
              color: agentMeta(log.agent).tint,
              whiteSpace: 'nowrap', flexShrink: 0, fontWeight: 700,
              fontSize: '0.7rem', letterSpacing: '0.05em',
            }}>
              {agentMeta(log.agent).symbol}{agentMeta(log.agent).name}
            </span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>›</span>
            <span style={{
              color: LEVEL_COLOR[log.level] || 'var(--text)',
              wordBreak: 'break-word',
            }}>
              {log.message}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
