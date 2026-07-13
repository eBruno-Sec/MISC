import { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionMode, ParsedScope, ScopeRule } from '../types'
import { AGENTS, PRODUCT_NAME } from '../brand'

const MODES: { id: MissionMode; label: string; desc: string; gates: string[] }[] = [
  {
    id: 'passive',
    label: 'Passive',
    desc: 'Reconnaissance only: CT logs, DNS, WHOIS, liveness checks, and technology hints.',
    gates: [],
  },
  {
    id: 'active',
    label: 'Active',
    desc: 'Reconnaissance plus active service and template checks against live targets.',
    gates: ['Tyr activation'],
  },
  {
    id: 'full',
    label: 'Full',
    desc: 'Complete assessment with active checks, payload preparation, impact review, and final report.',
    gates: ['Tyr activation', 'Brokkr activation', 'Skuld activation'],
  },
]

const SCOPE_EXAMPLE = `# One target per line. Prefix - to exclude.
example.com
*.example.com
- api-internal.example.com`

function ScopeRuleList({ rules, label, color }: { rules: ScopeRule[]; label: string; color: string }) {
  if (!rules.length) return null
  return (
    <div style={{ marginBottom: '0.85rem' }}>
      <div className="eyebrow" style={{ color, marginBottom: '0.45rem' }}>
        {label} ({rules.length})
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
        {rules.slice(0, 12).map((r, i) => (
          <span key={i} style={{
            fontSize: '0.78rem',
            padding: '0.25rem 0.55rem',
            background: `${color}12`,
            border: `1px solid ${color}30`,
            borderRadius: '999px',
            color,
          }}>{r.identifier}</span>
        ))}
        {rules.length > 12 && (
          <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '0.25rem 0.55rem' }}>
            +{rules.length - 12} more
          </span>
        )}
      </div>
    </div>
  )
}

export default function MissionLaunch() {
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState<MissionMode>('passive')
  const [scope, setScope] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [scopeTab, setScopeTab] = useState<'none' | 'upload' | 'paste'>('none')
  const [scopePaste, setScopePaste] = useState('')
  const [parsedScope, setParsedScope] = useState<ParsedScope | null>(null)
  const [parseLoading, setParseLoading] = useState(false)
  const [parseError, setParseError] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const navigate = useNavigate()

  const handleParse = useCallback(async (input: File | string) => {
    setParseError('')
    setParseLoading(true)
    try {
      const result = await api.parseScope(input)
      setParsedScope(result)
    } catch {
      setParseError('Could not parse scope. Check the format and try again.')
    } finally {
      setParseLoading(false)
    }
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleParse(file)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleParse(file)
  }

  const launch = async () => {
    if (!target.trim()) { setError('Target required'); return }
    setError('')
    setLoading(true)
    try {
      const scope_rules = parsedScope
        ? { in_scope: parsedScope.in_scope, out_of_scope: parsedScope.out_of_scope }
        : {}
      const { id } = await api.createMission(target.trim(), mode, scope, scope_rules)
      navigate(`/mission/${id}`)
    } catch (e: any) {
      setError(e.message || 'Launch failed')
      setLoading(false)
    }
  }

  const selectedMode = MODES.find(m => m.id === mode)!

  const tabBtn = (id: typeof scopeTab, label: string) => (
    <button
      onClick={() => { setScopeTab(id); if (id === 'none') setParsedScope(null) }}
      style={{
        fontSize: '0.78rem',
        padding: '0.45rem 0.8rem',
        border: '1px solid',
        borderColor: scopeTab === id ? 'var(--accent)' : 'var(--border2)',
        background: scopeTab === id ? 'var(--accent-dim)' : 'var(--surface)',
        color: scopeTab === id ? 'var(--accent)' : 'var(--text-dim)',
        fontWeight: 700,
      }}
    >{label}</button>
  )

  return (
    <main style={{ maxWidth: '980px', margin: '0 auto', padding: '3rem 1.25rem 4rem' }}>
      <section style={{ marginBottom: '1.5rem' }}>
        <div className="eyebrow" style={{ marginBottom: '0.6rem' }}>New Assessment</div>
        <h1 style={{ fontSize: '2.25rem', lineHeight: 1.1, fontWeight: 850, color: 'var(--text-bright)', marginBottom: '0.65rem' }}>
          Start a {PRODUCT_NAME} run
        </h1>
        <p style={{ fontSize: '0.95rem', color: 'var(--text-dim)', lineHeight: 1.7, maxWidth: '650px' }}>
          Keep the scope tight, pick the assessment depth, and move through approval gates when active checks are requested.
        </p>
      </section>

      <section className="soft-panel" style={{ padding: '1rem', marginBottom: '1.5rem' }}>
        <div className="eyebrow" style={{ marginBottom: '0.75rem' }}>Runbook</div>
        <div style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap' }}>
          {AGENTS.map((agent, i) => (
            <span key={agent.key} style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                fontSize: '0.78rem',
                padding: '0.38rem 0.62rem',
                background: 'var(--surface2)',
                border: '1px solid var(--border)',
                borderRadius: '999px',
                color: 'var(--text-bright)',
                fontWeight: 700,
              }}>
                <span style={{ color: agent.tint }}>{agent.symbol}</span>{agent.name}
              </span>
              {i < AGENTS.length - 1 && <span style={{ color: 'var(--border2)' }}>/</span>}
            </span>
          ))}
        </div>
      </section>

      <section className="soft-panel" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
        <div style={{ marginBottom: '1.25rem' }}>
          <label className="eyebrow" style={{ display: 'block', marginBottom: '0.55rem' }}>Target Domain or IP</label>
          <input
            type="text" value={target} onChange={e => setTarget(e.target.value)}
            placeholder="example.com"
            onKeyDown={e => e.key === 'Enter' && launch()}
            style={{ width: '100%', fontSize: '1rem', padding: '0.85rem 1rem' }}
            autoFocus
          />
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <label className="eyebrow" style={{ display: 'block', marginBottom: '0.75rem' }}>Assessment Mode</label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '0.75rem' }}>
            {MODES.map(m => (
              <button key={m.id} onClick={() => setMode(m.id)} style={{
                padding: '1rem',
                textAlign: 'left',
                background: mode === m.id ? 'var(--accent-dim)' : 'var(--surface)',
                border: `1px solid ${mode === m.id ? 'var(--accent)' : 'var(--border)'}`,
                boxShadow: mode === m.id ? '0 10px 24px rgba(47,117,102,0.10)' : 'none',
              }}>
                <div style={{ fontSize: '0.95rem', color: mode === m.id ? 'var(--accent)' : 'var(--text-bright)', marginBottom: '0.45rem', fontWeight: 800 }}>
                  {m.label}
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)', lineHeight: 1.55, marginBottom: m.gates.length ? '0.65rem' : 0 }}>
                  {m.desc}
                </div>
                {m.gates.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                    {m.gates.map(g => (
                      <span key={g} style={{ fontSize: '0.72rem', color: 'var(--gold)', background: 'var(--gold-dim)', padding: '0.2rem 0.45rem', borderRadius: '999px' }}>
                        {g}
                      </span>
                    ))}
                  </div>
                )}
              </button>
            ))}
          </div>
          <div style={{ marginTop: '0.7rem', fontSize: '0.82rem', color: 'var(--text-dim)' }}>
            Selected: <strong style={{ color: 'var(--text-bright)' }}>{selectedMode.label}</strong>
          </div>
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <label className="eyebrow" style={{ display: 'block', marginBottom: '0.55rem' }}>Scope Notes</label>
          <textarea
            value={scope} onChange={e => setScope(e.target.value)}
            placeholder="Example: All subdomains of example.com. Exclude pay.example.com."
            rows={3}
            style={{ width: '100%', resize: 'vertical' }}
          />
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
            <label className="eyebrow">Scope Rules</label>
            <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
              {tabBtn('none', 'None')}
              {tabBtn('upload', 'Upload CSV')}
              {tabBtn('paste', 'Paste')}
            </div>
          </div>

          {scopeTab === 'upload' && (
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              style={{
                border: `1px dashed ${dragOver ? 'var(--accent)' : 'var(--border2)'}`,
                background: dragOver ? 'var(--accent-dim)' : 'var(--surface2)',
                padding: '2rem',
                textAlign: 'center',
                cursor: 'pointer',
                borderRadius: 'var(--radius)',
              }}
            >
              <div style={{ fontSize: '0.95rem', color: 'var(--text-bright)', marginBottom: '0.25rem', fontWeight: 750 }}>
                Drop a scope file here
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)' }}>
                HackerOne, Bugcrowd, Intigriti, generic CSV, or plain text
              </div>
              <input ref={fileRef} type="file" accept=".csv,.txt" onChange={handleFileChange} style={{ display: 'none' }} />
            </div>
          )}

          {scopeTab === 'paste' && (
            <div>
              <textarea
                value={scopePaste}
                onChange={e => setScopePaste(e.target.value)}
                placeholder={SCOPE_EXAMPLE}
                rows={6}
                style={{ width: '100%', resize: 'vertical', fontSize: '0.82rem' }}
              />
              <button
                onClick={() => scopePaste.trim() && handleParse(scopePaste)}
                disabled={parseLoading || !scopePaste.trim()}
                style={{
                  marginTop: '0.6rem',
                  padding: '0.5rem 0.9rem',
                  border: '1px solid var(--accent)',
                  background: 'var(--accent-dim)',
                  color: 'var(--accent)',
                  fontWeight: 750,
                }}
              >
                {parseLoading ? 'Parsing...' : 'Parse Scope'}
              </button>
            </div>
          )}

          {parseLoading && <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '0.75rem' }}>Parsing scope...</div>}
          {parseError && <div style={{ fontSize: '0.82rem', color: 'var(--accent2)', marginTop: '0.75rem' }}>{parseError}</div>}

          {parsedScope && (
            <div style={{ marginTop: '0.9rem', padding: '1rem', background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '0.85rem' }}>
                <span className="eyebrow" style={{ color: 'var(--accent3)' }}>
                  Scope Parsed ({parsedScope.format_detected.toUpperCase()})
                </span>
                <button
                  onClick={() => { setParsedScope(null); setScopePaste(''); setScopeTab('none') }}
                  style={{ fontSize: '0.78rem', color: 'var(--text-dim)', cursor: 'pointer' }}
                >Clear</button>
              </div>
              <ScopeRuleList rules={parsedScope.in_scope} label="In Scope" color="var(--accent3)" />
              <ScopeRuleList rules={parsedScope.out_of_scope} label="Out of Scope" color="var(--accent2)" />
            </div>
          )}
        </div>
      </section>

      <section style={{
        padding: '0.9rem 1rem',
        marginBottom: '1rem',
        background: 'var(--gold-dim)',
        border: '1px solid rgba(184,129,54,0.25)',
        borderRadius: 'var(--radius)',
        fontSize: '0.82rem',
        color: 'var(--text)',
        lineHeight: 1.65,
      }}>
        By starting this assessment you confirm you have written authorization to test the specified target.
      </section>

      {error && <div style={{ fontSize: '0.86rem', color: 'var(--accent2)', marginBottom: '1rem' }}>{error}</div>}

      <button
        onClick={launch} disabled={loading}
        className="primary-action"
        style={{ width: '100%', padding: '0.95rem', fontSize: '0.95rem' }}
      >
        {loading ? 'Starting assessment...' : 'Start Assessment'}
      </button>
    </main>
  )
}
