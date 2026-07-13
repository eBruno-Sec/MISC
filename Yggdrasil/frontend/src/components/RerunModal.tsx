import { useState } from 'react'

interface Props {
  missionId: string
  agentName: string
  agentSymbol: string
  agentRole: string
  onConfirm: (targets?: string[], options?: object) => void
  onClose: () => void
}

export default function RerunModal({ missionId, agentName, agentSymbol, agentRole, onConfirm, onClose }: Props) {
  const [targetsText, setTargetsText] = useState('')
  const [nmapFlags, setNmapFlags] = useState('')
  const [nucleiSeverity, setNucleiSeverity] = useState('critical,high,medium')
  const [submitting, setSubmitting] = useState(false)
  const showAresOptions = agentName === 'ares'

  const run = async () => {
    setSubmitting(true)
    const targets = targetsText.trim()
      ? targetsText.split(/[\n,]+/).map(t => t.trim()).filter(Boolean)
      : undefined
    const options: Record<string, string> = {}
    if (showAresOptions) {
      if (nmapFlags.trim()) options.nmap_flags = nmapFlags.trim()
      if (nucleiSeverity.trim()) options.nuclei_severity = nucleiSeverity.trim()
    }
    onConfirm(targets, Object.keys(options).length ? options : undefined)
    onClose()
    setSubmitting(false)
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 300,
      background: 'rgba(2,6,8,0.88)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem',
    }}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border2)',
        maxWidth: '500px', width: '100%',
        animation: 'fade-in-up 0.15s ease',
      }}>
        <div style={{
          padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.2rem' }}>{agentSymbol}</span>
            <div>
              <div style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.15rem' }}>RE-RUN AGENT</div>
              <div style={{ fontSize: '0.95rem', color: 'var(--text-bright)', fontWeight: 700 }}>
                {agentName.toUpperCase()} — {agentRole}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ fontSize: '0.9rem', color: 'var(--text-dim)', cursor: 'pointer' }}>✕</button>
        </div>

        <div style={{ padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.62rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
              TARGET OVERRIDE (optional — blank runs on all mission hosts)
            </label>
            <textarea
              value={targetsText}
              onChange={e => setTargetsText(e.target.value)}
              placeholder="One host per line: sub.domain.com, 10.0.0.5"
              rows={3}
              style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem' }}
            />
          </div>

          {showAresOptions && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.62rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
                  NMAP FLAGS (optional)
                </label>
                <input
                  value={nmapFlags}
                  onChange={e => setNmapFlags(e.target.value)}
                  placeholder="-p 80,443,8080-8090 -sV"
                  style={{ width: '100%', fontSize: '0.8rem' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.62rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
                  NUCLEI SEVERITY FILTER
                </label>
                <input
                  value={nucleiSeverity}
                  onChange={e => setNucleiSeverity(e.target.value)}
                  placeholder="critical,high,medium,low"
                  style={{ width: '100%', fontSize: '0.8rem' }}
                />
                <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '0.3rem' }}>
                  Comma-separated. Options: critical, high, medium, low, info
                </div>
              </div>
            </>
          )}
        </div>

        <div style={{ padding: '0 1.5rem 1.25rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border)' }}>
          <button
            onClick={onClose}
            style={{ padding: '0.8rem', fontSize: '0.78rem', letterSpacing: '0.1em', background: 'var(--surface2)', color: 'var(--text-dim)', border: 'none', cursor: 'pointer' }}
          >CANCEL</button>
          <button
            onClick={run}
            disabled={submitting}
            style={{ padding: '0.8rem', fontSize: '0.78rem', letterSpacing: '0.1em', background: 'var(--accent-dim)', color: 'var(--accent)', border: 'none', cursor: 'pointer', fontWeight: 700 }}
          >⚡ RUN</button>
        </div>
      </div>
    </div>
  )
}
