import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { AccessCheckResult, FuzzResult, HttpExchange, ReplayResult } from '../types'

type View = 'replay' | 'fuzz' | 'access' | 'evidence'

interface Props {
  missionId: string
  target: string
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

function defaultUrl(target: string) {
  const clean = target.trim()
  if (!clean) return 'https://example.com/'
  if (clean.startsWith('http://') || clean.startsWith('https://')) return clean
  return `https://${clean}/`
}

function parseHeaders(text: string): Record<string, string> {
  const trimmed = text.trim()
  if (!trimmed) return {}
  try {
    const parsed = JSON.parse(trimmed)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
    return Object.fromEntries(Object.entries(parsed).map(([k, v]) => [k, String(v)]))
  } catch {
    const headers: Record<string, string> = {}
    for (const line of trimmed.split(/\r?\n/)) {
      const idx = line.indexOf(':')
      if (idx <= 0) continue
      headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
    }
    return headers
  }
}

function ResponseBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ border: '1px solid var(--border)', background: 'var(--surface2)', minHeight: 0 }}>
      <div className="eyebrow" style={{ padding: '0.55rem 0.75rem', borderBottom: '1px solid var(--border)' }}>{title}</div>
      <div style={{ padding: '0.75rem', overflow: 'auto' }}>{children}</div>
    </div>
  )
}

function MethodSelect({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} style={{ width: '112px', fontSize: '0.82rem', padding: '0.55rem 0.65rem' }}>
      {METHODS.map(method => <option key={method} value={method}>{method}</option>)}
    </select>
  )
}

export default function WorkbenchPanel({ missionId, target }: Props) {
  const [view, setView] = useState<View>('replay')
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState(defaultUrl(target))
  const [headers, setHeaders] = useState('')
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null)

  const [fuzzParameter, setFuzzParameter] = useState('id')
  const [payloads, setPayloads] = useState('1\n2\n../yggdrasil-canary.txt')
  const [fuzzResult, setFuzzResult] = useState<FuzzResult | null>(null)

  const [highHeaders, setHighHeaders] = useState('')
  const [lowHeaders, setLowHeaders] = useState('')
  const [accessResult, setAccessResult] = useState<AccessCheckResult | null>(null)

  const [exchanges, setExchanges] = useState<HttpExchange[]>([])
  const [selectedExchange, setSelectedExchange] = useState<HttpExchange | null>(null)
  const [poc, setPoc] = useState('')

  const exchangeCount = exchanges.length

  const loadExchanges = useCallback(async () => {
    try {
      const rows = await api.listHttpExchanges(missionId)
      setExchanges(rows)
      if (selectedExchange && !rows.some(row => row.id === selectedExchange.id)) setSelectedExchange(null)
    } catch {}
  }, [missionId, selectedExchange])

  useEffect(() => { loadExchanges() }, [loadExchanges])

  const headerHelp = useMemo(() => '{"Accept":"application/json"} or Header: value lines', [])

  const runReplay = async () => {
    setBusy(true)
    setError('')
    try {
      const result = await api.replayRequest(missionId, {
        method,
        url,
        headers: parseHeaders(headers),
        body: body || null,
        timeout: 15,
      })
      setReplayResult(result)
      await loadExchanges()
    } catch (err: any) {
      setError(err?.message || 'Replay failed')
    } finally {
      setBusy(false)
    }
  }

  const runFuzz = async () => {
    const list = payloads.split(/\r?\n/).map(p => p.trim()).filter(Boolean)
    setBusy(true)
    setError('')
    try {
      const result = await api.fuzzRequest(missionId, {
        method,
        url,
        parameter: fuzzParameter,
        payloads: list,
        headers: parseHeaders(headers),
        timeout: 10,
      })
      setFuzzResult(result)
    } catch (err: any) {
      setError(err?.message || 'Fuzz failed')
    } finally {
      setBusy(false)
    }
  }

  const runAccess = async () => {
    setBusy(true)
    setError('')
    try {
      const result = await api.accessCheck(missionId, {
        method,
        url,
        high_priv_headers: parseHeaders(highHeaders),
        low_priv_headers: parseHeaders(lowHeaders),
        body: body || null,
        timeout: 15,
      })
      setAccessResult(result)
      await loadExchanges()
    } catch (err: any) {
      setError(err?.message || 'Access check failed')
    } finally {
      setBusy(false)
    }
  }

  const loadPoc = async (exchange: HttpExchange) => {
    setSelectedExchange(exchange)
    setPoc('')
    try {
      const result = await api.getHttpExchangePoc(missionId, exchange.id)
      setPoc(result.markdown)
    } catch (err: any) {
      setPoc(err?.message || 'PoC unavailable')
    }
  }

  const TabBtn = ({ id, label, count }: { id: View; label: string; count?: number }) => (
    <button
      onClick={() => setView(id)}
      style={{
        fontSize: '0.78rem',
        padding: '0.5rem 0.7rem',
        border: '1px solid',
        borderColor: view === id ? 'var(--accent)' : 'transparent',
        background: view === id ? 'var(--accent-dim)' : 'transparent',
        color: view === id ? 'var(--accent)' : 'var(--text-dim)',
        fontWeight: 750,
      }}
    >{label}{count !== undefined ? ` (${count})` : ''}</button>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, background: 'var(--surface)' }}>
      <div style={{ display: 'flex', gap: '0.35rem', padding: '0.55rem', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <TabBtn id="replay" label="Replay" />
        <TabBtn id="fuzz" label="Fuzz" />
        <TabBtn id="access" label="Access" />
        <TabBtn id="evidence" label="Evidence" count={exchangeCount || undefined} />
      </div>

      <div style={{ padding: '0.75rem', borderBottom: '1px solid var(--border)', display: 'grid', gridTemplateColumns: '112px minmax(180px, 1fr)', gap: '0.55rem' }}>
        <MethodSelect value={method} onChange={setMethod} />
        <input value={url} onChange={e => setUrl(e.target.value)} style={{ fontSize: '0.82rem', padding: '0.55rem 0.7rem', minWidth: 0 }} />
      </div>

      {error && <div style={{ padding: '0.6rem 0.85rem', color: 'var(--accent2)', background: 'var(--surface2)', borderBottom: '1px solid var(--border)', fontSize: '0.82rem' }}>{error}</div>}

      <div style={{ flex: 1, overflow: 'auto', padding: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {view === 'replay' && (
          <>
            <textarea value={headers} onChange={e => setHeaders(e.target.value)} placeholder={headerHelp} rows={4} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            <textarea value={body} onChange={e => setBody(e.target.value)} placeholder="Request body" rows={5} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            <button onClick={runReplay} disabled={busy || !url.trim()} className="primary-action" style={{ alignSelf: 'flex-start', padding: '0.55rem 0.95rem', fontSize: '0.82rem' }}>{busy ? 'Running...' : 'Send Replay'}</button>
            {replayResult && (
              <ResponseBlock title={`Response ${replayResult.status_code}`}>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.78rem', fontFamily: 'var(--mono)' }}>{replayResult.body || '(empty)'}</pre>
              </ResponseBlock>
            )}
          </>
        )}

        {view === 'fuzz' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 220px) 1fr', gap: '0.65rem' }}>
              <input value={fuzzParameter} onChange={e => setFuzzParameter(e.target.value)} placeholder="parameter" style={{ fontSize: '0.82rem', padding: '0.55rem 0.7rem' }} />
              <textarea value={headers} onChange={e => setHeaders(e.target.value)} placeholder={headerHelp} rows={3} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            </div>
            <textarea value={payloads} onChange={e => setPayloads(e.target.value)} placeholder="One payload per line" rows={7} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            <button onClick={runFuzz} disabled={busy || !url.trim() || !fuzzParameter.trim()} className="primary-action" style={{ alignSelf: 'flex-start', padding: '0.55rem 0.95rem', fontSize: '0.82rem' }}>{busy ? 'Running...' : 'Run Fuzz'}</button>
            {fuzzResult && (
              <ResponseBlock title={`Fuzz results (${fuzzResult.count})`}>
                <div style={{ display: 'grid', gap: '0.45rem' }}>
                  {fuzzResult.results.map((item, i) => (
                    <div key={`${item.payload}-${i}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 1fr) auto auto', gap: '0.65rem', fontSize: '0.78rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.45rem' }}>
                      <span style={{ color: 'var(--text-bright)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.payload}</span>
                      <span style={{ color: item.error ? 'var(--accent2)' : 'var(--accent3)' }}>{item.error || item.status_code}</span>
                      <span style={{ color: 'var(--text-dim)' }}>{item.length ?? ''}</span>
                    </div>
                  ))}
                </div>
              </ResponseBlock>
            )}
          </>
        )}

        {view === 'access' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
              <textarea value={highHeaders} onChange={e => setHighHeaders(e.target.value)} placeholder="High-privilege headers" rows={7} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
              <textarea value={lowHeaders} onChange={e => setLowHeaders(e.target.value)} placeholder="Low-privilege headers" rows={7} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            </div>
            <textarea value={body} onChange={e => setBody(e.target.value)} placeholder="Request body" rows={4} style={{ width: '100%', resize: 'vertical', fontSize: '0.8rem', fontFamily: 'var(--mono)' }} />
            <button onClick={runAccess} disabled={busy || !url.trim()} className="primary-action" style={{ alignSelf: 'flex-start', padding: '0.55rem 0.95rem', fontSize: '0.82rem' }}>{busy ? 'Running...' : 'Run Access Check'}</button>
            {accessResult && (
              <ResponseBlock title="Access verdict">
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.78rem', fontFamily: 'var(--mono)' }}>{JSON.stringify(accessResult, null, 2)}</pre>
              </ResponseBlock>
            )}
          </>
        )}

        {view === 'evidence' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 0.85fr) minmax(260px, 1.15fr)', gap: '0.85rem', minHeight: 0 }}>
            <div style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
              <div style={{ padding: '0.55rem 0.75rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="eyebrow">HTTP Exchanges</span>
                <button onClick={loadExchanges} style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>Refresh</button>
              </div>
              <div style={{ maxHeight: '430px', overflow: 'auto' }}>
                {exchanges.length === 0 && <div style={{ padding: '1.5rem', color: 'var(--text-dim)', fontSize: '0.82rem', textAlign: 'center' }}>No exchanges recorded.</div>}
                {exchanges.map(exchange => (
                  <button
                    key={exchange.id}
                    onClick={() => loadPoc(exchange)}
                    style={{ width: '100%', display: 'block', textAlign: 'left', padding: '0.65rem 0.75rem', border: 'none', borderBottom: '1px solid var(--border)', background: selectedExchange?.id === exchange.id ? 'var(--accent-dim)' : 'var(--surface)', color: 'var(--text)', cursor: 'pointer' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <strong style={{ color: 'var(--text-bright)', fontSize: '0.78rem' }}>{exchange.method} {exchange.response_status ?? '?'}</strong>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>{new Date(exchange.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.76rem', color: 'var(--text-dim)' }}>{exchange.url}</div>
                  </button>
                ))}
              </div>
            </div>
            <ResponseBlock title={selectedExchange ? 'Markdown PoC' : 'PoC'}>
              <pre style={{ margin: 0, minHeight: '360px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.78rem', fontFamily: 'var(--mono)' }}>{poc || 'Select an exchange.'}</pre>
            </ResponseBlock>
          </div>
        )}
      </div>
    </div>
  )
}
