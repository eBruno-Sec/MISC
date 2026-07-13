import { useState, useEffect } from 'react'
import { api } from '../api'
import type { OraclePlan, OracleAI } from '../types'

const CATEGORIES = [
  '', 'SQL injection', 'Cross-site scripting', 'CSRF', 'Clickjacking',
  'SSRF', 'OS command injection', 'Path traversal', 'File upload',
  'Authentication', 'Access control', 'Business logic', 'Information disclosure',
  'JWT', 'OAuth', 'SSTI', 'Insecure deserialization', 'XXE', 'GraphQL',
  'Web cache poisoning', 'HTTP request smuggling', 'Prototype pollution',
  'Race conditions', 'NoSQL injection', 'API testing', 'Web LLM attacks',
]

const label: React.CSSProperties = {
  display: 'block', fontSize: '0.62rem', letterSpacing: '0.2em',
  color: 'var(--text-dim)', marginBottom: '0.4rem',
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setDone(true)
          setTimeout(() => setDone(false), 1200)
        } catch { /* clipboard blocked */ }
      }}
      style={{
        fontSize: '0.62rem', letterSpacing: '0.15em', padding: '0.2rem 0.6rem',
        border: `1px solid ${done ? 'var(--accent3)' : 'var(--border2)'}`,
        color: done ? 'var(--accent3)' : 'var(--text-dim)',
        background: done ? 'var(--accent3-dim)' : 'transparent',
        transition: 'all 0.12s', whiteSpace: 'nowrap',
      }}
    >{done ? 'COPIED' : 'COPY'}</button>
  )
}

function DifficultyBadge({ difficulty }: { difficulty: string }) {
  if (!difficulty) return null
  const d = difficulty.toLowerCase()
  const color = d.includes('expert') ? 'var(--crit)'
    : d.includes('pract') ? 'var(--med)' : 'var(--accent)'
  return (
    <span style={{
      fontSize: '0.6rem', letterSpacing: '0.15em', padding: '0.2rem 0.6rem',
      border: `1px solid ${color}`, color, background: 'transparent',
      textTransform: 'uppercase',
    }}>{difficulty}</span>
  )
}

function PlanView({ plan }: { plan: OraclePlan }) {
  const card: React.CSSProperties = {
    background: 'var(--surface2)', border: '1px solid var(--border)',
    padding: '1.1rem 1.25rem', marginBottom: '1rem',
  }
  const heading: React.CSSProperties = {
    fontSize: '0.62rem', letterSpacing: '0.22em', color: 'var(--accent)',
    marginBottom: '0.75rem',
  }

  if (plan.raw && !plan.steps.length && !plan.payloads.length) {
    return (
      <div style={card}>
        <div style={heading}>ORACLE ANALYSIS</div>
        <pre style={{
          whiteSpace: 'pre-wrap', fontSize: '0.8rem', lineHeight: 1.7,
          color: 'var(--text)', fontFamily: 'var(--mono)',
        }}>{plan.raw}</pre>
      </div>
    )
  }

  return (
    <div className="fade-in">
      <div style={{ ...card, borderLeft: '2px solid var(--accent)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.6rem', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--display)', fontWeight: 800, fontSize: '1.1rem', color: 'var(--text-bright)' }}>
            {plan.vulnerability || 'Exploit Plan'}
          </span>
          <DifficultyBadge difficulty={plan.difficulty} />
        </div>
        {plan.summary && (
          <div style={{ fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.7 }}>{plan.summary}</div>
        )}
      </div>

      {plan.steps.length > 0 && (
        <div style={card}>
          <div style={heading}>EXPLOIT STEPS</div>
          <ol style={{ margin: 0, paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {plan.steps.map((s, i) => (
              <li key={i} style={{ fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.65 }}>{s}</li>
            ))}
          </ol>
        </div>
      )}

      {plan.payloads.length > 0 && (
        <div style={card}>
          <div style={heading}>PAYLOADS</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {plan.payloads.map((p, i) => (
              <div key={i}>
                {p.label && (
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>{p.label}</div>
                )}
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch' }}>
                  <code style={{
                    flex: 1, background: 'var(--bg)', border: '1px solid var(--border2)',
                    padding: '0.5rem 0.7rem', fontSize: '0.8rem', color: 'var(--accent3)',
                    overflowX: 'auto', whiteSpace: 'pre',
                  }}>{p.value}</code>
                  <CopyBtn text={p.value} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {plan.request && (
        <div style={card}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <span style={heading}>RAW REQUEST · SEND FROM BURP REPEATER</span>
            <CopyBtn text={plan.request} />
          </div>
          <pre style={{
            background: 'var(--bg)', border: '1px solid var(--border2)', padding: '0.8rem',
            fontSize: '0.78rem', lineHeight: 1.6, color: 'var(--text)', overflowX: 'auto',
            whiteSpace: 'pre', fontFamily: 'var(--mono)',
          }}>{plan.request}</pre>
        </div>
      )}

      {plan.success_indicator && (
        <div style={{ ...card, borderLeft: '2px solid var(--accent3)' }}>
          <div style={{ ...heading, color: 'var(--accent3)' }}>SOLVED WHEN</div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.7 }}>{plan.success_indicator}</div>
        </div>
      )}

      {plan.notes && (
        <div style={card}>
          <div style={{ ...heading, color: 'var(--gold)' }}>NOTES</div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.7 }}>{plan.notes}</div>
        </div>
      )}
    </div>
  )
}

export default function Oracle() {
  const [labTitle, setLabTitle] = useState('')
  const [category, setCategory] = useState('')
  const [labUrl, setLabUrl] = useState('')
  const [description, setDescription] = useState('')
  const [request, setRequest] = useState('')
  const [showReq, setShowReq] = useState(false)

  const [plan, setPlan] = useState<OraclePlan | null>(null)
  const [ai, setAi] = useState<OracleAI | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [followText, setFollowText] = useState('')
  const [followResp, setFollowResp] = useState('')
  const [following, setFollowing] = useState(false)

  useEffect(() => {
    api.oracleStatus().then(setAi).catch(() => setAi(null))
  }, [])

  const solve = async () => {
    if (!labTitle.trim() && !description.trim()) {
      setError('Give ORACLE a lab title or description to work from.')
      return
    }
    setError(''); setLoading(true); setPlan(null)
    try {
      const res = await api.oracleSolve({
        lab_title: labTitle.trim(), category, lab_url: labUrl.trim(),
        description: description.trim(), captured_request: request.trim(),
      })
      setPlan(res.plan); setAi(res.ai)
    } catch (e: any) {
      setError(e.message || 'ORACLE request failed')
    } finally {
      setLoading(false)
    }
  }

  const followup = async () => {
    if (!followText.trim() || !plan) return
    setFollowing(true); setError('')
    try {
      const res = await api.oracleFollowup({
        lab_title: labTitle.trim(), description: description.trim(),
        prior: plan, what_happened: followText.trim(), captured_response: followResp.trim(),
      })
      setPlan(res.plan); setAi(res.ai)
      setFollowText(''); setFollowResp('')
    } catch (e: any) {
      setError(e.message || 'Follow-up failed')
    } finally {
      setFollowing(false)
    }
  }

  return (
    <main style={{ maxWidth: '880px', margin: '0 auto', padding: '3rem 2rem' }}>
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ fontSize: '0.65rem', letterSpacing: '0.3em', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>COMPANION</div>
        <h1 style={{ fontFamily: 'var(--display)', fontSize: '2.2rem', fontWeight: 900, color: 'var(--text-bright)', marginBottom: '0.5rem' }}>
          🔮 The Oracle
        </h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.8 }}>
          Paste a PortSwigger Academy lab. ORACLE returns the vulnerability, the exact exploit steps,
          ready payloads, and the raw request to fire from Burp. You send it. It advises.
        </p>
      </div>

      {ai && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1.5rem',
          fontSize: '0.68rem', color: ai.configured ? 'var(--text-dim)' : 'var(--accent2)',
        }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            background: ai.configured ? 'var(--accent3)' : 'var(--accent2)',
          }} />
          {ai.configured
            ? <span>ORACLE online · {ai.provider} · {ai.model}</span>
            : <span>No AI key configured. Set AI_PROVIDER and AI_API_KEY in .env.</span>}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        <div>
          <label style={label}>LAB TITLE</label>
          <input value={labTitle} onChange={e => setLabTitle(e.target.value)}
            placeholder="e.g. Blind SQL injection with conditional responses"
            style={{ width: '100%' }} />
        </div>
        <div>
          <label style={label}>CATEGORY</label>
          <select value={category} onChange={e => setCategory(e.target.value)} style={{ width: '100%' }}>
            {CATEGORIES.map(c => <option key={c} value={c}>{c || 'auto-detect'}</option>)}
          </select>
        </div>
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <label style={label}>LAB URL (optional)</label>
        <input value={labUrl} onChange={e => setLabUrl(e.target.value)}
          placeholder="https://YOUR-LAB-ID.web-security-academy.net/" style={{ width: '100%' }} />
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <label style={label}>LAB DESCRIPTION</label>
        <textarea value={description} onChange={e => setDescription(e.target.value)}
          placeholder="Paste the lab's description / objective text from PortSwigger."
          rows={4} style={{ width: '100%', resize: 'vertical' }} />
      </div>

      <div style={{ marginBottom: '1.25rem' }}>
        <button onClick={() => setShowReq(!showReq)}
          style={{ fontSize: '0.68rem', letterSpacing: '0.15em', color: 'var(--text-dim)' }}>
          {showReq ? '− ' : '+ '}CAPTURED REQUEST (optional)
        </button>
        {showReq && (
          <textarea value={request} onChange={e => setRequest(e.target.value)}
            placeholder="Paste a raw request from Burp if you have one. Helps ORACLE target the exact parameter."
            rows={6} style={{ width: '100%', resize: 'vertical', marginTop: '0.5rem', fontSize: '0.78rem' }} />
        )}
      </div>

      {error && <div style={{ fontSize: '0.8rem', color: 'var(--accent2)', marginBottom: '1rem' }}>✕ {error}</div>}

      <button onClick={solve} disabled={loading}
        style={{
          width: '100%', padding: '0.95rem', marginBottom: '2rem',
          background: loading ? 'var(--accent-dim)' : 'var(--accent)',
          color: loading ? 'var(--accent)' : 'var(--bg)',
          fontSize: '0.82rem', letterSpacing: '0.25em', fontFamily: 'var(--display)', fontWeight: 900,
          border: '1px solid var(--accent)', cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'all 0.15s',
        }}>
        {loading ? '🔮 CONSULTING...' : '🔮 CONSULT ORACLE'}
      </button>

      {plan && <PlanView plan={plan} />}

      {plan && (
        <div style={{
          marginTop: '1.5rem', padding: '1.1rem 1.25rem',
          background: 'var(--surface)', border: '1px solid var(--border)',
        }}>
          <div style={{ fontSize: '0.62rem', letterSpacing: '0.22em', color: 'var(--accent2)', marginBottom: '0.75rem' }}>
            DIDN'T SOLVE IT? TELL ORACLE WHAT HAPPENED
          </div>
          <textarea value={followText} onChange={e => setFollowText(e.target.value)}
            placeholder="e.g. The payload returned a 500 instead of a delay. The filter stripped single quotes."
            rows={3} style={{ width: '100%', resize: 'vertical', marginBottom: '0.6rem' }} />
          <textarea value={followResp} onChange={e => setFollowResp(e.target.value)}
            placeholder="Optional: paste the response you saw."
            rows={3} style={{ width: '100%', resize: 'vertical', marginBottom: '0.75rem', fontSize: '0.78rem' }} />
          <button onClick={followup} disabled={following || !followText.trim()}
            style={{
              fontSize: '0.72rem', letterSpacing: '0.18em', padding: '0.55rem 1.2rem',
              border: '1px solid var(--accent2)', color: 'var(--accent2)',
              background: 'var(--accent2-dim)', cursor: following ? 'not-allowed' : 'pointer',
            }}>
            {following ? 'REFINING...' : 'REFINE EXPLOIT'}
          </button>
        </div>
      )}
    </main>
  )
}
