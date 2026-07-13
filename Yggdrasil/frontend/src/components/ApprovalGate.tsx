import { useEffect, useState } from 'react'
import type { ApprovalRequest } from '../types'
import { api } from '../api'
import { agentMeta } from '../brand'

interface Props {
  missionId: string
  approvals: ApprovalRequest[]
  onResolved: () => void
}

export default function ApprovalGate({ missionId, approvals, onResolved }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const approval = approvals[0]

  useEffect(() => {
    setLoading(false)
    setError('')
  }, [approval?.id])

  if (!approval) return null

  const agent = agentMeta(approval.agent)

  const resolve = async (approved: boolean) => {
    setLoading(true)
    setError('')
    try {
      const result = await api.resolveApproval(missionId, approval.id, approved)
      onResolved()
      if (result.status === 'stale') {
        setError(result.detail || 'This approval is stale because the backend restarted. Relaunch the mission.')
      }
    } catch (e: any) {
      setError(e?.message || 'Could not resolve approval. Refresh the mission and try again.')
      onResolved()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 200,
      background: 'rgba(20, 36, 30, 0.45)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1rem',
      backdropFilter: 'blur(8px)',
    }}>
      <div className="soft-panel" style={{ maxWidth: '560px', width: '100%', animation: 'fade-in-up 0.2s ease', overflow: 'hidden' }}>
        <div style={{
          padding: '1rem 1.25rem',
          background: 'var(--gold-dim)',
          borderBottom: '1px solid rgba(184,129,54,0.25)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.85rem',
        }}>
          <span style={{
            width: '2.3rem',
            height: '2.3rem',
            borderRadius: '50%',
            background: 'var(--surface)',
            color: agent.tint,
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 850,
          }}>{agent.symbol}</span>
          <div>
            <div className="eyebrow" style={{ color: 'var(--gold)', marginBottom: '0.18rem' }}>Authorization Check</div>
            <div style={{ fontSize: '1rem', color: 'var(--text-bright)', fontWeight: 800 }}>
              {agent.name} requests approval
            </div>
          </div>
        </div>

        <div style={{ padding: '1.25rem' }}>
          <div style={{ marginBottom: '1rem' }}>
            <div className="eyebrow" style={{ marginBottom: '0.4rem' }}>Requested Action</div>
            <div style={{ fontSize: '0.95rem', color: 'var(--text-bright)', fontWeight: 700 }}>{approval.action}</div>
          </div>

          {approval.description && (
            <div style={{ marginBottom: '1.25rem' }}>
              <div className="eyebrow" style={{ marginBottom: '0.4rem' }}>Details</div>
              <div style={{
                fontSize: '0.86rem',
                color: 'var(--text)',
                lineHeight: 1.75,
                background: 'var(--surface2)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '0.9rem 1rem',
              }}>
                {approval.description}
              </div>
            </div>
          )}

          <div style={{
            padding: '0.75rem 0.9rem',
            marginBottom: error ? '0.75rem' : '1.25rem',
            background: 'var(--accent2-dim)',
            border: '1px solid rgba(184,92,80,0.2)',
            borderRadius: 'var(--radius)',
            fontSize: '0.8rem',
            color: 'var(--text)',
            lineHeight: 1.65,
          }}>
            This action can send active traffic to the target. Yggdrasil will wait here until you authorize or deny it.
          </div>

          {error && (
            <div style={{
              marginBottom: '1.25rem',
              padding: '0.7rem 0.85rem',
              background: 'var(--surface2)',
              border: '1px solid rgba(184,92,80,0.28)',
              borderRadius: 'var(--radius)',
              color: 'var(--accent2)',
              fontSize: '0.82rem',
              lineHeight: 1.5,
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <button
              onClick={() => resolve(false)}
              disabled={loading}
              style={{
                padding: '0.8rem',
                fontSize: '0.88rem',
                fontWeight: 800,
                background: 'var(--surface2)',
                color: 'var(--accent2)',
                border: '1px solid var(--border)',
              }}
            >
              {loading ? 'Working...' : 'Deny'}
            </button>
            <button
              onClick={() => resolve(true)}
              disabled={loading}
              style={{
                padding: '0.8rem',
                fontSize: '0.88rem',
                fontWeight: 800,
                background: 'var(--accent)',
                color: '#fff',
                border: '1px solid var(--accent)',
              }}
            >
              {loading ? 'Working...' : 'Authorize'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
