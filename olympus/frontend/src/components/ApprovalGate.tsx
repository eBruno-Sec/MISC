import { useState } from 'react'
import type { ApprovalRequest } from '../types'
import { api } from '../api'

interface Props {
  missionId: string
  approvals: ApprovalRequest[]
  onResolved: () => void
}

const AGENT_SYMBOL: Record<string, string> = {
  zeus: '⚡', athena: '🦉', hermes: '☿', ares: '⚔',
  hephaestus: '🔥', hades: '💀', apollo: '☀',
}

export default function ApprovalGate({ missionId, approvals, onResolved }: Props) {
  const [loading, setLoading] = useState(false)

  if (approvals.length === 0) return null

  const approval = approvals[0]
  const symbol = AGENT_SYMBOL[approval.agent] || '●'

  const resolve = async (approved: boolean) => {
    setLoading(true)
    try {
      await api.resolveApproval(missionId, approval.id, approved)
      onResolved()
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 200,
      background: 'rgba(2, 6, 8, 0.92)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '1rem',
    }}>
      <div style={{
        background: 'var(--surface)',
        border: '1px solid var(--gold)',
        boxShadow: '0 0 40px rgba(245,158,11,0.15)',
        maxWidth: '560px', width: '100%',
        animation: 'fade-in-up 0.2s ease',
      }}>
        <div style={{
          padding: '1rem 1.5rem',
          background: 'rgba(245,158,11,0.08)',
          borderBottom: '1px solid rgba(245,158,11,0.2)',
          display: 'flex', alignItems: 'center', gap: '0.75rem',
        }}>
          <span style={{ fontSize: '1.2rem' }}>{symbol}</span>
          <div>
            <div style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--gold)', marginBottom: '0.2rem' }}>HUMAN-IN-THE-LOOP GATE</div>
            <div style={{ fontSize: '0.9rem', color: 'var(--text-bright)', fontWeight: 700 }}>
              {approval.agent.toUpperCase()} requests authorization
            </div>
          </div>
        </div>

        <div style={{ padding: '1.5rem' }}>
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>REQUESTED ACTION</div>
            <div style={{ fontSize: '0.9rem', color: 'var(--text-bright)' }}>{approval.action}</div>
          </div>

          {approval.description && (
            <div style={{ marginBottom: '1.5rem' }}>
              <div style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>DETAILS</div>
              <div style={{
                fontSize: '0.8rem', color: 'var(--text)', lineHeight: 1.8,
                background: 'var(--surface2)', border: '1px solid var(--border)',
                padding: '0.9rem 1rem',
              }}>
                {approval.description}
              </div>
            </div>
          )}

          <div style={{
            padding: '0.75rem 1rem', marginBottom: '1.5rem',
            background: 'var(--accent2-dim)', border: '1px solid rgba(255,61,107,0.2)',
            fontSize: '0.72rem', color: 'var(--text-dim)', lineHeight: 1.8,
          }}>
            ⚠ This action initiates active operations against the target. Ensure you have valid written authorization before proceeding.
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border)' }}>
            <button
              onClick={() => resolve(false)}
              disabled={loading}
              style={{
                padding: '0.9rem', fontSize: '0.8rem', letterSpacing: '0.15em',
                fontFamily: 'var(--display)', fontWeight: 700,
                background: 'var(--surface2)', color: 'var(--accent2)',
                border: 'none', cursor: 'pointer', transition: 'all 0.1s',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--accent2-dim)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--surface2)' }}
            >
              ✕ DENY
            </button>
            <button
              onClick={() => resolve(true)}
              disabled={loading}
              style={{
                padding: '0.9rem', fontSize: '0.8rem', letterSpacing: '0.15em',
                fontFamily: 'var(--display)', fontWeight: 700,
                background: 'var(--accent-dim)', color: 'var(--accent)',
                border: 'none', cursor: 'pointer', transition: 'all 0.1s',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,229,255,0.2)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-dim)' }}
            >
              ✓ AUTHORIZE
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
