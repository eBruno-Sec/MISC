import { useState, type CSSProperties } from 'react'
import { api } from '../api'
import type { ReplayResult, FuzzResult, FuzzHit } from '../types'

// Repeater + Intruder in the browser. Craft a request, replay it (captured as
// evidence), or fuzz one parameter with a curated wordlist and read the ranked
// anomalies. Deterministic — no AI. Paste a URL from the SURFACE tab's COPY.

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

const WORDLISTS = ['sqli', 'xss', 'lfi', 'redirect', 'ssti']

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
  textTransform: 'uppercase', display: 'block', margin: '0.6rem 0 0.25rem',
}
const preStyle: CSSProperties = {
  background: 'var(--bg)', border: '1px solid var(--border2)', padding: '0.6rem',
  fontSize: '0.72rem', color: 'var(--accent3)', maxHeight: 240, overflow: 'auto',
  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
}
const th: CSSProperties = {
  textAlign: 'left', padding: '0.35rem 0.5rem', color: 'var(--text-dim)',
  fontSize: '0.58rem', letterSpacing: '0.1em', textTransform: 'uppercase',
  borderBottom: '1px solid var(--border)',
}
const td: CSSProperties = { padding: '0.3rem 0.5rem', color: 'var(--text)' }

function statusColor(s: number): string {
  if (s >= 500) return 'var(--accent2)'
  if (s >= 400) return 'var(--gold)'
  if (s >= 300) return 'var(--accent)'
  return 'var(--accent3)'
}

function FuzzRow({ h }: { h: FuzzHit }) {
  const sigs = h.error_signatures && h.error_signatures.length ? h.error_signatures[0] : ''
  const signal = h.error ? `error: ${h.error}` : [sigs, h.reflected ? 'reflected' : ''].filter(Boolean).join(', ')
  const hot = (h.score ?? 0) >= 4
  return (
    <tr style={{ borderBottom: '1px solid var(--border)', background: hot ? 'var(--accent2-dim)' : 'transparent' }}>
      <td style={{ ...td, color: hot ? 'var(--accent2)' : 'var(--text-dim)', fontWeight: hot ? 700 : 400 }}>{h.score ?? 0}</td>
      <td style={{ ...td, fontFamily: 'var(--mono)', color: 'var(--text-bright)', wordBreak: 'break-all' }}>{h.payload}</td>
      <td style={td}>{h.status ?? '—'}</td>
      <td style={td}>{h.length ?? '—'}</td>
      <td style={td}>{h.duration_ms ?? '—'}</td>
      <td style={{ ...td, color: 'var(--gold)' }}>{signal}</td>
    </tr>
  )
}

export default function WorkbenchPanel({ missionId }: { missionId: string }) {
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [bodyText, setBodyText] = useState('')
  const [replayRes, setReplayRes] = useState<ReplayResult | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  const [param, setParam] = useState('')
  const [paramIn, setParamIn] = useState('query')
  const [wordlist, setWordlist] = useState('sqli')
  const [fuzzRes, setFuzzRes] = useState<FuzzResult | null>(null)

  const doReplay = async () => {
    if (!url.trim()) { setError('Enter a URL'); return }
    setError(''); setBusy('replay'); setReplayRes(null)
    try {
      const r = await api.replay(missionId, {
        method, url: url.trim(), headers: parseHeaders(headersText),
        body: bodyText || null, save: true,
      })
      setReplayRes(r)
    } catch (e: any) { setError(e.message || 'Replay failed') }
    finally { setBusy('') }
  }

  const doFuzz = async () => {
    if (!url.trim() || !param.trim()) { setError('Need a URL and a parameter to fuzz'); return }
    setError(''); setBusy('fuzz'); setFuzzRes(null)
    try {
      const r = await api.fuzz(missionId, {
        method, url: url.trim(), headers: parseHeaders(headersText), body: bodyText || null,
        param: param.trim(), param_in: paramIn, wordlist_id: wordlist, max_payloads: 200,
      })
      setFuzzRes(r)
    } catch (e: any) { setError(e.message || 'Fuzz failed') }
    finally { setBusy('') }
  }

  return (
    <div style={{ padding: '0.75rem 1rem 1.5rem', overflow: 'auto' }}>
      {error && <div style={{ fontSize: '0.78rem', color: 'var(--accent2)', marginBottom: '0.5rem' }}>{error}</div>}

      <div style={{ display: 'flex', gap: '0.4rem' }}>
        <select value={method} onChange={e => setMethod(e.target.value)} style={{ ...inp, width: 'auto' }}>
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <input value={url} onChange={e => setUrl(e.target.value)}
          placeholder="http://juice-shop:3000/rest/products/search?q=test" style={inp} />
      </div>

      <label style={lbl}>Headers — one per line (Key: Value)</label>
      <textarea value={headersText} onChange={e => setHeadersText(e.target.value)} rows={3}
        placeholder={'Cookie: token=...\nAuthorization: Bearer ...'} style={{ ...inp, resize: 'vertical' }} />

      <label style={lbl}>Body</label>
      <textarea value={bodyText} onChange={e => setBodyText(e.target.value)} rows={2}
        style={{ ...inp, resize: 'vertical' }} />

      <div style={{ marginTop: '0.6rem' }}>
        <button onClick={doReplay} disabled={busy !== ''} style={btn}>
          {busy === 'replay' ? 'SENDING...' : '▶ REPLAY'}
        </button>
      </div>

      {replayRes && (
        <div style={{ marginTop: '0.75rem', border: '1px solid var(--border)', padding: '0.6rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
            <span style={{ color: statusColor(replayRes.status) }}>HTTP {replayRes.status}</span>
            {`  ·  ${replayRes.length} B  ·  ${replayRes.duration_ms} ms`}
            {replayRes.exchange_id ? '  ·  saved as evidence' : ''}
          </div>
          <pre style={preStyle}>{replayRes.body || '(empty body)'}</pre>
        </div>
      )}

      <div style={{ marginTop: '1.25rem', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
        <div style={{ fontSize: '0.6rem', letterSpacing: '0.2em', color: 'var(--accent2)', marginBottom: '0.4rem' }}>
          INTRUDER — FUZZ ONE PARAMETER
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <input value={param} onChange={e => setParam(e.target.value)} placeholder="param (e.g. q)"
            style={{ ...inp, width: '32%' }} />
          <select value={paramIn} onChange={e => setParamIn(e.target.value)} style={{ ...inp, width: 'auto' }}>
            {['query', 'body', 'header'].map(x => <option key={x} value={x}>{x}</option>)}
          </select>
          <select value={wordlist} onChange={e => setWordlist(e.target.value)} style={{ ...inp, width: 'auto' }}>
            {WORDLISTS.map(x => <option key={x} value={x}>{x}</option>)}
          </select>
          <button onClick={doFuzz} disabled={busy !== ''}
            style={{ ...btn, borderColor: 'var(--accent2)', color: 'var(--accent2)', background: 'var(--accent2-dim)' }}>
            {busy === 'fuzz' ? 'FUZZING...' : '⚡ FUZZ'}
          </button>
        </div>

        {fuzzRes && (
          <div style={{ marginTop: '0.6rem' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
              baseline HTTP {fuzzRes.baseline.status} · {fuzzRes.baseline.length} B — {fuzzRes.count} payloads, ranked by anomaly
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.74rem' }}>
                <thead><tr>{['Score', 'Payload', 'Status', 'Len', 'ms', 'Signal'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
                <tbody>{fuzzRes.results.slice(0, 60).map((h, i) => <FuzzRow key={i} h={h} />)}</tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
