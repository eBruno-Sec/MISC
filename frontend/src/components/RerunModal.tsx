import { useState } from 'react'
import { agentMeta } from '../brand'

interface Props {
  missionId: string
  agentName: string
  agentSymbol: string
  agentRole: string
  onConfirm: (targets?: string[], options?: object) => void
  onClose: () => void
}

export default function RerunModal({ agentName, agentSymbol, agentRole, onConfirm, onClose }: Props) {
  const [targetsText, setTargetsText] = useState('')
  const [nmapFlags, setNmapFlags] = useState('')
  const [nucleiSeverity, setNucleiSeverity] = useState('critical,high,medium')
  const [submitting, setSubmitting] = useState(false)
  const showTyrOptions = agentName === 'ares'
  const agent = agentMeta(agentName)
  const symbol = agentSymbol || agent.symbol
  const role = agentRole || agent.role

  const run = async () => {
    setSubmitting(true)
    const targets = targetsText.trim()
      ? targetsText.split(/[\n,]+/).map(t => t.trim()).filter(Boolean)
      : undefined
    const options: Record<string, string> = {}
    if (showTyrOptions) {
      if (nmapFlags.trim()) options.nmap_flags = nmapFlags.trim()
      if (nucleiSeverity.trim()) options.nuclei_severity = nucleiSeverity.trim()
    }
    onConfirm(targets, Object.keys(options).length ? options : undefined)
    onClose()
    setSubmitting(false)
  }

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 300,
      background: 'rgba(20,36,30,0.45)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1rem',
      backdropFilter: 'blur(8px)',
    }}>
      <div className="soft-panel" style={{ maxWidth: '500px', width: '100%', animation: 'fade-in-up 0.15s ease', overflow: 'hidden' }}>
        <div style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', minWidth: 0 }}>
            <span style={{
              width: '2.25rem',
              height: '2.25rem',
              borderRadius: '50%',
              background: 'var(--accent-dim)',
              color: agent.tint,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 850,
              flexShrink: 0,
            }}>{symbol}</span>
            <div style={{ minWidth: 0 }}>
              <div className="eyebrow" style={{ marginBottom: '0.18rem' }}>Re-run Stage</div>
              <div style={{ fontSize: '1rem', color: 'var(--text-bright)', fontWeight: 800 }}>
                {agent.name} - {role}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ fontSize: '0.88rem', color: 'var(--text-dim)', cursor: 'pointer' }}>Close</button>
        </div>

        <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label className="eyebrow" style={{ display: 'block', marginBottom: '0.45rem' }}>
              Target Override
            </label>
            <textarea
              value={targetsText}
              onChange={e => setTargetsText(e.target.value)}
              placeholder="One host per line: sub.domain.com, 10.0.0.5"
              rows={3}
              style={{ width: '100%', resize: 'vertical', fontSize: '0.82rem' }}
            />
            <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
              Leave blank to run on all mission hosts.
            </div>
          </div>

          {showTyrOptions && (
            <>
              <div>
                <label className="eyebrow" style={{ display: 'block', marginBottom: '0.45rem' }}>
                  Nmap Flags
                </label>
                <input
                  value={nmapFlags}
                  onChange={e => setNmapFlags(e.target.value)}
                  placeholder="-p 80,443,8080-8090 -sV"
                  style={{ width: '100%', fontSize: '0.82rem' }}
                />
              </div>
              <div>
                <label className="eyebrow" style={{ display: 'block', marginBottom: '0.45rem' }}>
                  Nuclei Severity Filter
                </label>
                <input
                  value={nucleiSeverity}
                  onChange={e => setNucleiSeverity(e.target.value)}
                  placeholder="critical,high,medium,low"
                  style={{ width: '100%', fontSize: '0.82rem' }}
                />
                <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
                  Comma-separated. Options: critical, high, medium, low, info.
                </div>
              </div>
            </>
          )}
        </div>

        <div style={{ padding: '0 1.25rem 1.25rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <button
            onClick={onClose}
            style={{ padding: '0.8rem', fontSize: '0.86rem', background: 'var(--surface2)', color: 'var(--text-dim)', border: '1px solid var(--border)', fontWeight: 750 }}
          >Cancel</button>
          <button
            onClick={run}
            disabled={submitting}
            style={{ padding: '0.8rem', fontSize: '0.86rem', background: 'var(--accent)', color: '#fff', border: '1px solid var(--accent)', fontWeight: 800 }}
          >Run Stage</button>
        </div>
      </div>
    </div>
  )
}
