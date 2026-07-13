import { useState, useEffect, useCallback, type CSSProperties } from 'react'
import { api } from '../api'
import type { AuthProfile, AccessRow, AccessResult } from '../types'

// Cross-role access control (IDOR / BOLA / BFLA). Register sessions (roles),
// then send the same request as each + anon and flag who reached the owner's
// data. Detections are candidates — confirm before reporting.

function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  text.split('\n').forEach(line => {
    const i = line.indexOf(':')
    if (i > 0) {
      const k = line.slice(0, i).trim()
      if (k) out[k] = line.slice(i + 1).trim()
    }
  })
  return out
}

const inp: CSSProperties = {
  width: '100%', padding: '0.45rem 0.6rem', background: 'var(--bg)',
  border: '1px solid var(--border2)', color: 'var(--text-bright)',
  fontSize: '0.78rem', fontFamily: 'var(--mono)',
}
const btn: CSSProperties = {
  fontSize: '0.68rem', letterSpacing: '0.12em', padding: '0.5rem 1rem',
  border: '1px solid var(--accent)', color: 'var(--accent)',
  background: 'var(--accent-dim)', cursor: 'pointer',
}
const lbl: CSSProperties = {
  fontSize: '0.6rem', letterSpacing: '0.15em', color: 'var(--text-dim)',
  textTransform: 'uppercase', display: 'block', margin: '0.5rem 0 0.25rem',
}
const td: CSSProperties = { padding: '0.35rem 0.5rem', color: 'var(--text)', fontSize: '0.76rem' }
const th: CSSProperties = {
  textAlign: 'left', padding: '0.35rem 0.5rem', color: 'var(--text-dim)',
  fontSize: '0.58rem', letterSpacing: '0.1em', textTransform: 'uppercase',
  borderBottom: '1px solid var(--border)',
}

function ResultRow({ r }: { r: AccessRow }) {
  const flagged = !!r.flag
  return (
    <tr style={{ borderBottom: '1px solid var(--border)', background: flagged ? 'var(--accent2-dim)' : 'transparent' }}>
      <td style={{ ...td, color: 'var(--text-bright)' }}>
        {r.role}{r.is_owner ? ' (owner)' : ''}
      </td>
      <td style={td}>{r.error ? 'ERR' : (r.status ?? '—')}</td>
      <td style={td}>{r.length ?? '—'}</td>
      <td style={{ ...td, color: flagged ? 'var(--accent2)' : 'var(--text-dim)', fontWeight: flagged ? 700 : 400 }}>
        {r.flag || (r.error ? r.error : 'ok')}
      </td>
    </tr>
  )
}

export default function AccessCheckPanel({ missionId }: { missionId: string }) {
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [name, setName] = useState('')
  const [role, setRole] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [owner, setOwner] = useState('')
  const [includeAnon, setIncludeAnon] = useState(true)
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<AccessResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try { const r = await api.listProfiles(missionId); setProfiles(r.profiles) }
    catch (e: any) { setError(e.message || 'Failed to load profiles') }
  }, [missionId])
  useEffect(() => { load() }, [load])

  const addProfile = async () => {
    if (!name.trim()) { setError('Profile needs a name'); return }
    setError('')
    try {
      await api.createProfile(missionId, {
        name: name.trim(), role: role.trim() || undefined, headers: parseHeaders(headersText),
      })
      setName(''); setRole(''); setHeadersText(''); load()
    } catch (e: any) { setError(e.message || 'Create failed') }
  }

  const del = async (id: string) => {
    try {
      await api.deleteProfile(missionId, id)
      setSelected(s => s.filter(x => x !== id))
      if (owner === id) setOwner('')
      load()
    } catch (e: any) { setError(e.message || 'Delete failed') }
  }

  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const run = async () => {
    if (!url.trim() || selected.length === 0) { setError('Need a URL and at least one role'); return }
    setError(''); setBusy(true); setResult(null)
    try {
      const r = await api.accessCheck(missionId, {
        method, url: url.trim(), profile_ids: selected,
        owner_profile_id: owner || undefined, include_anon: includeAnon,
      })
      setResult(r)
    } catch (e: any) { setError(e.message || 'Access check failed') }
    finally { setBusy(false) }
  }

  return (
    <div style={{ padding: '0.75rem 1rem 1.5rem', overflow: 'auto' }}>
      {error && <div style={{ fontSize: '0.78rem', color: 'var(--accent2)', marginBottom: '0.5rem' }}>{error}</div>}

      {/* Roles */}
      <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent)', marginBottom: '0.4rem' }}>
        ROLES ({profiles.length})
      </div>
      {profiles.map(p => (
        <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.3rem 0', borderBottom: '1px solid var(--border)' }}>
          <input type="checkbox" checked={selected.includes(p.id)} onChange={() => toggle(p.id)} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-bright)' }}>{p.name}</span>
            {p.role ? <span style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginLeft: '0.4rem' }}>{p.role}</span> : null}
          </div>
          <label style={{ fontSize: '0.6rem', color: 'var(--gold)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <input type="radio" name="owner" checked={owner === p.id} onChange={() => setOwner(p.id)} /> owner
          </label>
          <button onClick={() => del(p.id)}
            style={{ fontSize: '0.58rem', padding: '0.15rem 0.45rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', background: 'transparent', cursor: 'pointer' }}>
            DEL
          </button>
        </div>
      ))}

      {/* Add role */}
      <div style={{ marginTop: '0.6rem', display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        <input value={name} onChange={e => setName(e.target.value)} placeholder="name (user-a)" style={{ ...inp, width: '30%' }} />
        <input value={role} onChange={e => setRole(e.target.value)} placeholder="role (standard user)" style={{ ...inp, flex: 1 }} />
      </div>
      <textarea value={headersText} onChange={e => setHeadersText(e.target.value)} rows={2}
        placeholder={'Cookie: session=AAA'} style={{ ...inp, resize: 'vertical', marginTop: '0.4rem' }} />
      <div style={{ marginTop: '0.4rem' }}>
        <button onClick={addProfile} style={btn}>+ ADD ROLE</button>
      </div>

      {/* Check */}
      <div style={{ marginTop: '1.25rem', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
        <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent2)', marginBottom: '0.4rem' }}>
          ACCESS CHECK — SAME REQUEST AS EACH ROLE
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <select value={method} onChange={e => setMethod(e.target.value)} style={{ ...inp, width: 'auto' }}>
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m} value={m}>{m}</option>)}
          </select>
          <input value={url} onChange={e => setUrl(e.target.value)}
            placeholder="http://juice-shop:3000/api/Users/1" style={inp} />
        </div>
        <label style={{ ...lbl, display: 'flex', alignItems: 'center', gap: '0.4rem', textTransform: 'none', letterSpacing: 0, fontSize: '0.72rem', color: 'var(--text)' }}>
          <input type="checkbox" checked={includeAnon} onChange={e => setIncludeAnon(e.target.checked)} />
          include anon (no auth) as a control
        </label>
        <div style={{ marginTop: '0.4rem' }}>
          <button onClick={run} disabled={busy}
            style={{ ...btn, borderColor: 'var(--accent2)', color: 'var(--accent2)', background: 'var(--accent2-dim)' }}>
            {busy ? 'CHECKING...' : '⚖ RUN ACCESS CHECK'}
          </button>
        </div>

        {result && (
          <div style={{ marginTop: '0.7rem' }}>
            <div style={{
              fontSize: '0.78rem', padding: '0.5rem 0.7rem', marginBottom: '0.5rem',
              border: `1px solid ${result.anomaly ? 'var(--accent2)' : 'var(--border2)'}`,
              color: result.anomaly ? 'var(--accent2)' : 'var(--accent3)',
              background: result.anomaly ? 'var(--accent2-dim)' : 'transparent',
            }}>
              {result.verdict}
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead><tr>{['Role', 'Status', 'Len', 'Verdict'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
                <tbody>{result.results.map((r, i) => <ResultRow key={i} r={r} />)}</tbody>
              </table>
            </div>
            <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginTop: '0.5rem', lineHeight: 1.6 }}>
              Flagged rows are <strong style={{ color: 'var(--accent2)' }}>candidates</strong>, not confirmed findings.
              Every response was saved as evidence.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
