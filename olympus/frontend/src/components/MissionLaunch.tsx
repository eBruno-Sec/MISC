import { useState, useRef, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { MissionMode, ParsedScope, ScopeRule, Wordlist } from '../types'

const MODES: { id: MissionMode; label: string; desc: string; gates: string[] }[] = [
  {
    id: 'passive',
    label: 'PASSIVE',
    desc: 'OSINT only. Hermes maps attack surface via CT logs, DNS, WHOIS, live host detection.',
    gates: [],
  },
  {
    id: 'active',
    label: 'ACTIVE',
    desc: 'Passive recon + Ares runs Nmap and Nuclei templates on live targets.',
    gates: ['ARES activation'],
  },
  {
    id: 'full',
    label: 'FULL',
    desc: 'Complete assessment: recon → scanning → Hephaestus payload forge → Hades post-exploit analysis.',
    gates: ['ARES activation', 'HEPHAESTUS activation', 'HADES activation'],
  },
]

const GODS = ['⚡ ZEUS', '🦉 ATHENA', '☿ HERMES', '⚔ ARES', '🔥 HEPHAESTUS', '💀 HADES', '☀ APOLLO']

const SCOPE_EXAMPLE = `# One target per line. Prefix - to exclude.
example.com
*.example.com
- api-internal.example.com`

function ScopeRuleList({ rules, label, color }: { rules: ScopeRule[]; label: string; color: string }) {
  if (!rules.length) return null
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color, marginBottom: '0.35rem' }}>
        {label} ({rules.length})
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
        {rules.slice(0, 12).map((r, i) => (
          <span key={i} style={{
            fontSize: '0.7rem', padding: '0.15rem 0.5rem',
            background: `${color}10`, border: `1px solid ${color}30`, color,
          }}>{r.identifier}</span>
        ))}
        {rules.length > 12 && (
          <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', padding: '0.15rem 0.5rem' }}>
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
  const [autoApprove, setAutoApprove] = useState(false)
  const [scope, setScope] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Scope upload state
  const [scopeTab, setScopeTab] = useState<'none' | 'upload' | 'paste'>('none')
  const [scopePaste, setScopePaste] = useState('')
  const [parsedScope, setParsedScope] = useState<ParsedScope | null>(null)
  const [parseLoading, setParseLoading] = useState(false)
  const [parseError, setParseError] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const navigate = useNavigate()

  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const [selectedWl, setSelectedWl] = useState<string[]>([])

  useEffect(() => {
    api.listWordlists()
      .then(c => {
        setWordlists(c.wordlists.filter(w => ['content', 'api', 'fuzz'].includes(w.category)))
        setSelectedWl(c.default_content_ids)
      })
      .catch(() => {})
  }, [])

  const toggleWl = (id: string) =>
    setSelectedWl(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])

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
      const scope_rules: Record<string, any> = parsedScope
        ? { in_scope: parsedScope.in_scope, out_of_scope: parsedScope.out_of_scope }
        : {}
      if (selectedWl.length) scope_rules.wordlist_ids = selectedWl
      const { id } = await api.createMission(target.trim(), mode, scope, scope_rules, autoApprove)
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
        fontSize: '0.7rem', letterSpacing: '0.15em', padding: '0.35rem 0.9rem',
        border: '1px solid', cursor: 'pointer',
        borderColor: scopeTab === id ? 'var(--accent)' : 'var(--border2)',
        background: scopeTab === id ? 'var(--accent-dim)' : 'var(--surface)',
        color: scopeTab === id ? 'var(--accent)' : 'var(--text-dim)',
        transition: 'all 0.1s',
      }}
    >{label}</button>
  )

  return (
    <main style={{ maxWidth: '860px', margin: '0 auto', padding: '3rem 2rem' }}>
      <div style={{ marginBottom: '2.5rem' }}>
        <div style={{ fontSize: '0.65rem', letterSpacing: '0.3em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>MISSION CONTROL</div>
        <h1 style={{ fontFamily: 'var(--display)', fontSize: '2.2rem', fontWeight: 900, color: 'var(--text-bright)', marginBottom: '0.5rem' }}>Launch Mission</h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.8 }}>
          Authorized targets only. Define scope, select assessment mode, and OLYMPUS gods run in sequence.
        </p>
      </div>

      {/* God sequence */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '2.5rem', flexWrap: 'wrap' }}>
        {GODS.map((g, i) => (
          <span key={g} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem', background: 'var(--accent-dim)', border: '1px solid rgba(0,229,255,0.15)', color: 'var(--accent)' }}>{g}</span>
            {i < GODS.length - 1 && <span style={{ color: 'var(--border2)', fontSize: '0.75rem' }}>→</span>}
          </span>
        ))}
      </div>

      {/* Target */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>TARGET DOMAIN / IP</label>
        <input
          type="text" value={target} onChange={e => setTarget(e.target.value)}
          placeholder="example.com"
          onKeyDown={e => e.key === 'Enter' && launch()}
          style={{ width: '100%', fontSize: '1rem', padding: '0.75rem 1rem' }}
          autoFocus
        />
      </div>

      {/* Mode */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.75rem' }}>ASSESSMENT MODE</label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1px', background: 'var(--border)' }}>
          {MODES.map(m => (
            <div key={m.id} onClick={() => setMode(m.id)} style={{
              padding: '1.25rem', cursor: 'pointer',
              background: mode === m.id ? 'var(--accent-dim)' : 'var(--surface)',
              borderBottom: mode === m.id ? '2px solid var(--accent)' : '2px solid transparent',
              transition: 'all 0.15s',
            }}>
              <div style={{ fontSize: '0.8rem', color: mode === m.id ? 'var(--accent)' : 'var(--text-bright)', marginBottom: '0.4rem', fontWeight: 700, letterSpacing: '0.1em' }}>{m.label}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: m.gates.length ? '0.6rem' : 0 }}>{m.desc}</div>
              {m.gates.length > 0 && (
                <div style={{ fontSize: '0.65rem', color: 'var(--gold)', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  {m.gates.map(g => <span key={g}>⊳ HITL gate: {g}</span>)}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Autonomous mode: pre-authorize HITL gates (only meaningful when gates exist) */}
      {selectedMode.gates.length > 0 && (
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={autoApprove} onChange={e => setAutoApprove(e.target.checked)}
              style={{ marginTop: '0.2rem' }} />
            <span>
              <span style={{ fontSize: '0.82rem', color: autoApprove ? 'var(--accent2)' : 'var(--text-bright)' }}>
                Autonomous run — pre-authorize all HITL gates
              </span>
              <span style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '0.2rem', lineHeight: 1.5 }}>
                Skips the approve/deny prompts and lets {selectedMode.gates.join(', ')} run without stopping.
                Every gate is still logged. Only for targets you are authorized to test.
              </span>
            </span>
          </label>
        </div>
      )}

      {/* Scope notes */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>SCOPE NOTES (optional)</label>
        <textarea
          value={scope} onChange={e => setScope(e.target.value)}
          placeholder="e.g. All subdomains of example.com. Exclude pay.example.com."
          rows={2}
          style={{ width: '100%', resize: 'vertical' }}
        />
      </div>

      {/* Scope upload */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <label style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)' }}>SCOPE RULES</label>
          <div style={{ display: 'flex', gap: '1px' }}>
            {tabBtn('none', 'NONE')}
            {tabBtn('upload', 'UPLOAD CSV')}
            {tabBtn('paste', 'PASTE')}
          </div>
        </div>

        {scopeTab === 'upload' && (
          <div>
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              style={{
                border: `1px dashed ${dragOver ? 'var(--accent)' : 'var(--border2)'}`,
                background: dragOver ? 'var(--accent-dim)' : 'var(--surface)',
                padding: '2rem', textAlign: 'center', cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>📄</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>
                Drop CSV here or click to browse
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', opacity: 0.6 }}>
                HackerOne · Bugcrowd · Intigriti · generic CSV · plain text
              </div>
              <input ref={fileRef} type="file" accept=".csv,.txt" onChange={handleFileChange} style={{ display: 'none' }} />
            </div>
          </div>
        )}

        {scopeTab === 'paste' && (
          <div>
            <textarea
              value={scopePaste}
              onChange={e => setScopePaste(e.target.value)}
              placeholder={SCOPE_EXAMPLE}
              rows={5}
              style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--mono)', fontSize: '0.8rem' }}
            />
            <button
              onClick={() => scopePaste.trim() && handleParse(scopePaste)}
              disabled={parseLoading || !scopePaste.trim()}
              style={{
                marginTop: '0.5rem', fontSize: '0.72rem', letterSpacing: '0.15em',
                padding: '0.4rem 1rem', border: '1px solid var(--accent)',
                background: 'var(--accent-dim)', color: 'var(--accent)', cursor: 'pointer',
              }}
            >
              {parseLoading ? 'PARSING...' : 'PARSE SCOPE'}
            </button>
          </div>
        )}

        {parseLoading && <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '0.75rem' }}>Parsing scope...</div>}
        {parseError && <div style={{ fontSize: '0.78rem', color: 'var(--accent2)', marginTop: '0.75rem' }}>{parseError}</div>}

        {parsedScope && (
          <div style={{ marginTop: '0.75rem', padding: '1rem', background: 'var(--surface2)', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--accent3)' }}>
                SCOPE PARSED ({parsedScope.format_detected.toUpperCase()})
              </span>
              <button
                onClick={() => { setParsedScope(null); setScopePaste(''); setScopeTab('none') }}
                style={{ fontSize: '0.7rem', color: 'var(--text-dim)', cursor: 'pointer' }}
              >clear</button>
            </div>
            <ScopeRuleList rules={parsedScope.in_scope} label="IN SCOPE" color="var(--accent3)" />
            <ScopeRuleList rules={parsedScope.out_of_scope} label="OUT OF SCOPE" color="var(--accent2)" />
          </div>
        )}
      </div>

      {/* Wordlists */}
      {wordlists.length > 0 && (
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'block', fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.75rem' }}>
            CONTENT-DISCOVERY WORDLISTS
          </label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {wordlists.map(w => {
              const on = selectedWl.includes(w.id)
              return (
                <button
                  key={w.id}
                  type="button"
                  onClick={() => toggleWl(w.id)}
                  title={w.exists ? `${w.count.toLocaleString()} entries` : 'not present on server'}
                  style={{
                    fontSize: '0.7rem', letterSpacing: '0.05em', padding: '0.3rem 0.7rem',
                    border: `1px solid ${on ? 'var(--accent)' : 'var(--border2)'}`,
                    background: on ? 'var(--accent-dim)' : 'var(--surface)',
                    color: on ? 'var(--accent)' : 'var(--text-dim)',
                    opacity: w.exists ? 1 : 0.5, cursor: 'pointer', transition: 'all 0.1s',
                  }}
                >
                  {on ? '✓ ' : ''}{w.name}
                </button>
              )
            })}
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', marginTop: '0.5rem', lineHeight: 1.6 }}>
            ARES pairs these with a target-specific list HEPHAESTUS generates from recon. Defaults preselected.
          </div>
        </div>
      )}

      {/* Authorization warning */}
      <div style={{
        padding: '0.9rem 1.2rem', marginBottom: '1.5rem',
        background: 'var(--accent2-dim)', border: '1px solid rgba(255,61,107,0.2)',
        fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.8,
      }}>
        ⚠ By launching this mission you confirm you have written authorization to perform security testing against the specified target. Unauthorized scanning may violate the CFAA and equivalent laws.
      </div>

      {error && <div style={{ fontSize: '0.8rem', color: 'var(--accent2)', marginBottom: '1rem' }}>✕ {error}</div>}

      <button
        onClick={launch} disabled={loading}
        style={{
          width: '100%', padding: '1rem',
          background: loading ? 'var(--accent-dim)' : 'var(--accent)',
          color: loading ? 'var(--accent)' : 'var(--bg)',
          fontSize: '0.85rem', letterSpacing: '0.25em',
          fontFamily: 'var(--display)', fontWeight: 900,
          border: '1px solid var(--accent)',
          cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'all 0.15s',
        }}
      >
        {loading ? '⚡ INITIALIZING...' : '⚡ LAUNCH MISSION'}
      </button>
    </main>
  )
}
