import { useState } from 'react'
import { api } from '../api'
import type { Finding, Severity, FindingTag } from '../types'

const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--crit)', high: 'var(--high)',
  medium: 'var(--med)', low: 'var(--low)', info: 'var(--info)',
}

const TAG_CONFIG: Record<string, { label: string; color: string }> = {
  confirmed:      { label: 'CONFIRMED',       color: 'var(--accent3)' },
  false_positive: { label: 'FALSE POSITIVE',  color: 'var(--text-dim)' },
  reported:       { label: 'REPORTED',        color: 'var(--gold)' },
  fixed:          { label: 'FIXED',           color: '#6b7280' },
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const TAGS: (FindingTag | 'all')[] = ['all', 'confirmed', 'reported', 'fixed', 'false_positive']

interface AddFindingForm {
  title: string; severity: Severity; description: string;
  evidence: string; cvss_score: string; remediation: string;
}

interface Props {
  missionId: string
  findings: Finding[]
  onUpdate: (id: string, data: Partial<Finding>) => void
  onDelete: (id: string) => void
  onAdd: (f: Finding) => void
}

export default function FindingsPanel({ missionId, findings, onUpdate, onDelete, onAdd }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [tagFilter, setTagFilter] = useState<FindingTag | 'all'>('all')
  const [editing, setEditing] = useState<string | null>(null)
  const [editData, setEditData] = useState<Partial<Finding>>({})
  const [showAdd, setShowAdd] = useState(false)
  const [addForm, setAddForm] = useState<AddFindingForm>({
    title: '', severity: 'medium', description: '', evidence: '', cvss_score: '', remediation: '',
  })
  const [saving, setSaving] = useState(false)

  const toggle = (id: string) => setExpanded(prev => {
    const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n
  })

  const stats = SEV_ORDER.reduce((a, s) => ({ ...a, [s]: findings.filter(f => f.severity === s).length }), {} as Record<Severity, number>)

  const visible = findings
    .filter(f => f.tag !== 'false_positive' || tagFilter === 'false_positive')
    .filter(f => sevFilter === 'all' || f.severity === sevFilter)
    .filter(f => tagFilter === 'all' || f.tag === tagFilter || (tagFilter === null && !f.tag))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))

  const cycleTag = async (f: Finding) => {
    const cycle: (FindingTag)[] = [null, 'confirmed', 'reported', 'fixed', 'false_positive']
    const cur = cycle.indexOf(f.tag)
    const next = cycle[(cur + 1) % cycle.length]
    try {
      await api.updateFinding(missionId, f.id, { tag: next })
      onUpdate(f.id, { tag: next })
    } catch {}
  }

  const saveEdit = async (id: string) => {
    setSaving(true)
    try {
      await api.updateFinding(missionId, id, editData)
      onUpdate(id, editData)
      setEditing(null)
      setEditData({})
    } catch {}
    setSaving(false)
  }

  const del = async (id: string) => {
    if (!confirm('Delete this finding?')) return
    try {
      await api.deleteFinding(missionId, id)
      onDelete(id)
    } catch {}
  }

  const submitAdd = async () => {
    if (!addForm.title.trim()) return
    setSaving(true)
    try {
      const f = await api.addFinding(missionId, {
        title: addForm.title.trim(),
        severity: addForm.severity,
        description: addForm.description || undefined,
        evidence: addForm.evidence || undefined,
        cvss_score: addForm.cvss_score ? parseFloat(addForm.cvss_score) : undefined,
        remediation: addForm.remediation || undefined,
      }) as Finding
      onAdd(f)
      setShowAdd(false)
      setAddForm({ title: '', severity: 'medium', description: '', evidence: '', cvss_score: '', remediation: '' })
    } catch {}
    setSaving(false)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '0.5rem 0.75rem', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem',
      }}>
        <span style={{ fontSize: '0.62rem', letterSpacing: '0.15em', color: 'var(--text-dim)' }}>
          FINDINGS ({findings.filter(f => f.tag !== 'false_positive').length})
        </span>
        <button
          onClick={() => setShowAdd(true)}
          style={{ fontSize: '0.62rem', letterSpacing: '0.12em', padding: '0.2rem 0.55rem', border: '1px solid var(--accent)', color: 'var(--accent)', background: 'var(--accent-dim)', cursor: 'pointer' }}
        >+ ADD</button>
      </div>

      {/* Severity pills */}
      <div style={{ display: 'flex', gap: '1px', background: 'var(--border)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <button onClick={() => setSevFilter('all')} style={{ flex: 1, padding: '0.4rem 0.25rem', fontSize: '0.6rem', background: sevFilter === 'all' ? 'var(--surface2)' : 'var(--surface)', color: sevFilter === 'all' ? 'var(--text-bright)' : 'var(--text-dim)', border: 'none', cursor: 'pointer', letterSpacing: '0.05em' }}>ALL {findings.length}</button>
        {SEV_ORDER.map(s => (
          <button key={s} onClick={() => setSevFilter(sevFilter === s ? 'all' : s)} style={{ flex: 1, padding: '0.4rem 0.25rem', fontSize: '0.6rem', background: sevFilter === s ? `${SEV_COLOR[s]}18` : 'var(--surface)', color: stats[s] > 0 ? SEV_COLOR[s] : 'var(--border2)', border: 'none', cursor: 'pointer', borderBottom: sevFilter === s ? `2px solid ${SEV_COLOR[s]}` : '2px solid transparent' }}>
            {s.slice(0, 4).toUpperCase()} {stats[s]}
          </button>
        ))}
      </div>

      {/* Tag filter */}
      <div style={{ display: 'flex', gap: '0.35rem', padding: '0.4rem 0.75rem', background: 'var(--surface)', borderBottom: '1px solid var(--border)', overflowX: 'auto', flexShrink: 0 }}>
        {TAGS.map(t => (
          <button key={String(t)} onClick={() => setTagFilter(tagFilter === t ? 'all' : t as any)} style={{
            fontSize: '0.6rem', padding: '0.15rem 0.5rem', whiteSpace: 'nowrap', cursor: 'pointer', border: '1px solid',
            borderColor: tagFilter === t ? (t === 'all' ? 'var(--accent)' : (TAG_CONFIG[t as string]?.color || 'var(--accent)')) : 'var(--border2)',
            background: tagFilter === t ? 'rgba(0,229,255,0.08)' : 'transparent',
            color: t === 'all' ? 'var(--text-dim)' : (TAG_CONFIG[t as string]?.color || 'var(--text-dim)'),
          }}>
            {t === 'all' ? 'ALL TAGS' : TAG_CONFIG[t as string]?.label || String(t).toUpperCase()}
          </button>
        ))}
      </div>

      {/* Finding list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {visible.length === 0 && (
          <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.78rem' }}>No findings</div>
        )}
        {visible.map(f => {
          const color = SEV_COLOR[f.severity]
          const isEdit = editing === f.id
          const isFP = f.tag === 'false_positive'
          return (
            <div key={f.id} style={{ borderBottom: '1px solid var(--border)', opacity: isFP ? 0.5 : 1 }}>
              <div
                onClick={() => { if (!isEdit) toggle(f.id) }}
                style={{ padding: '0.65rem 0.75rem', cursor: isEdit ? 'default' : 'pointer', display: 'flex', alignItems: 'flex-start', gap: '0.6rem', background: expanded.has(f.id) ? 'var(--surface2)' : 'transparent' }}
              >
                <span style={{ fontSize: '0.55rem', padding: '0.15rem 0.35rem', background: `${color}15`, border: `1px solid ${color}40`, color, flexShrink: 0, marginTop: '2px', letterSpacing: '0.08em' }}>
                  {f.severity.toUpperCase()}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-bright)', textDecoration: isFP ? 'line-through' : 'none', wordBreak: 'break-word' }}>
                    {f.is_manual && <span style={{ fontSize: '0.58rem', color: 'var(--gold)', marginRight: '0.4rem' }}>MANUAL</span>}
                    {f.title}
                  </div>
                  {f.tag && (
                    <span style={{ fontSize: '0.58rem', color: TAG_CONFIG[f.tag]?.color || 'var(--text-dim)', letterSpacing: '0.1em' }}>
                      {TAG_CONFIG[f.tag]?.label}
                    </span>
                  )}
                </div>
                {/* Action buttons */}
                <div style={{ display: 'flex', gap: '0.3rem', flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                  <button
                    title="Cycle tag"
                    onClick={() => cycleTag(f)}
                    style={{ fontSize: '0.65rem', padding: '0.15rem 0.35rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', cursor: 'pointer', background: 'transparent' }}
                  >Tag</button>
                  <button
                    title="Edit"
                    onClick={() => { setEditing(isEdit ? null : f.id); setEditData({ severity: f.severity, title: f.title, description: f.description ?? '', evidence: f.evidence ?? '', remediation: f.remediation ?? '', analyst_notes: f.analyst_notes ?? '' }) }}
                    style={{ fontSize: '0.65rem', padding: '0.15rem 0.35rem', border: '1px solid var(--border2)', color: isEdit ? 'var(--accent)' : 'var(--text-dim)', cursor: 'pointer', background: isEdit ? 'var(--accent-dim)' : 'transparent' }}
                  >Edit</button>
                  <button
                    title="Delete"
                    onClick={() => del(f.id)}
                    style={{ fontSize: '0.65rem', padding: '0.15rem 0.35rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', cursor: 'pointer', background: 'transparent' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent2)'; e.currentTarget.style.color = 'var(--accent2)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border2)'; e.currentTarget.style.color = 'var(--text-dim)' }}
                  >Delete</button>
                </div>
              </div>

              {isEdit && (
                <div style={{ padding: '0.75rem', background: 'var(--surface2)', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <select value={editData.severity || f.severity} onChange={e => setEditData(p => ({ ...p, severity: e.target.value as Severity }))} style={{ fontSize: '0.78rem', padding: '0.3rem' }}>
                    {SEV_ORDER.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
                  </select>
                  <input value={editData.title ?? ''} onChange={e => setEditData(p => ({ ...p, title: e.target.value }))} placeholder="Title" style={{ fontSize: '0.78rem' }} />
                  <textarea value={editData.description ?? ''} onChange={e => setEditData(p => ({ ...p, description: e.target.value }))} placeholder="Description" rows={2} style={{ fontSize: '0.78rem', resize: 'none' }} />
                  <textarea value={editData.evidence ?? ''} onChange={e => setEditData(p => ({ ...p, evidence: e.target.value }))} placeholder="Evidence" rows={2} style={{ fontSize: '0.78rem', resize: 'none' }} />
                  <textarea value={editData.remediation ?? ''} onChange={e => setEditData(p => ({ ...p, remediation: e.target.value }))} placeholder="Remediation" rows={2} style={{ fontSize: '0.78rem', resize: 'none' }} />
                  <textarea value={editData.analyst_notes ?? ''} onChange={e => setEditData(p => ({ ...p, analyst_notes: e.target.value }))} placeholder="Analyst notes (internal)" rows={2} style={{ fontSize: '0.78rem', resize: 'none', borderColor: 'rgba(245,158,11,0.3)' }} />
                  <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                    <button onClick={() => { setEditing(null); setEditData({}) }} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', cursor: 'pointer' }}>Cancel</button>
                    <button onClick={() => saveEdit(f.id)} disabled={saving} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', background: 'var(--accent)', color: 'var(--bg)', border: 'none', cursor: 'pointer' }}>Save</button>
                  </div>
                </div>
              )}

              {expanded.has(f.id) && !isEdit && (
                <div style={{ padding: '0.65rem 0.75rem', background: 'var(--surface)', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                  {f.cvss_score != null && <div style={{ fontSize: '0.68rem', color: 'var(--gold)' }}>CVSS {f.cvss_score.toFixed(1)}</div>}
                  {f.description && <div><div style={{ fontSize: '0.58rem', letterSpacing: '0.15em', color: 'var(--accent)', marginBottom: '0.2rem' }}>DESCRIPTION</div><p style={{ fontSize: '0.78rem', color: 'var(--text)', lineHeight: 1.8 }}>{f.description}</p></div>}
                  {f.evidence && <div><div style={{ fontSize: '0.58rem', letterSpacing: '0.15em', color: 'var(--accent)', marginBottom: '0.2rem' }}>EVIDENCE</div><pre style={{ fontSize: '0.7rem', color: 'var(--accent3)', background: 'var(--surface2)', padding: '0.5rem', overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>{f.evidence}</pre></div>}
                  {f.remediation && <div><div style={{ fontSize: '0.58rem', letterSpacing: '0.15em', color: 'var(--accent)', marginBottom: '0.2rem' }}>REMEDIATION</div><p style={{ fontSize: '0.78rem', color: 'var(--text)', lineHeight: 1.8 }}>{f.remediation}</p></div>}
                  {f.analyst_notes && <div style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', padding: '0.5rem 0.65rem' }}><div style={{ fontSize: '0.58rem', color: 'var(--gold)', letterSpacing: '0.15em', marginBottom: '0.2rem' }}>ANALYST NOTES</div><p style={{ fontSize: '0.78rem', color: 'var(--gold)', lineHeight: 1.8 }}>{f.analyst_notes}</p></div>}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Add finding modal */}
      {showAdd && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 300, background: 'rgba(2,6,8,0.88)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem' }}>
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border2)', maxWidth: '520px', width: '100%', animation: 'fade-in-up 0.15s ease' }}>
            <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--accent)' }}>ADD MANUAL FINDING</span>
              <button onClick={() => setShowAdd(false)} style={{ cursor: 'pointer', color: 'var(--text-dim)' }}>Close</button>
            </div>
            <div style={{ padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              <input value={addForm.title} onChange={e => setAddForm(p => ({ ...p, title: e.target.value }))} placeholder="Title *" style={{ fontSize: '0.88rem' }} />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                <select value={addForm.severity} onChange={e => setAddForm(p => ({ ...p, severity: e.target.value as Severity }))} style={{ fontSize: '0.82rem' }}>
                  {SEV_ORDER.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
                </select>
                <input value={addForm.cvss_score} onChange={e => setAddForm(p => ({ ...p, cvss_score: e.target.value }))} placeholder="CVSS score (e.g. 8.1)" style={{ fontSize: '0.82rem' }} />
              </div>
              <textarea value={addForm.description} onChange={e => setAddForm(p => ({ ...p, description: e.target.value }))} placeholder="Description" rows={3} style={{ fontSize: '0.82rem', resize: 'none' }} />
              <textarea value={addForm.evidence} onChange={e => setAddForm(p => ({ ...p, evidence: e.target.value }))} placeholder="Evidence / PoC" rows={3} style={{ fontSize: '0.82rem', resize: 'none' }} />
              <textarea value={addForm.remediation} onChange={e => setAddForm(p => ({ ...p, remediation: e.target.value }))} placeholder="Remediation" rows={2} style={{ fontSize: '0.82rem', resize: 'none' }} />
            </div>
            <div style={{ padding: '0 1.5rem 1.25rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border)' }}>
              <button onClick={() => setShowAdd(false)} style={{ padding: '0.8rem', fontSize: '0.78rem', background: 'var(--surface2)', color: 'var(--text-dim)', border: 'none', cursor: 'pointer' }}>CANCEL</button>
              <button onClick={submitAdd} disabled={saving || !addForm.title.trim()} style={{ padding: '0.8rem', fontSize: '0.78rem', background: 'var(--accent)', color: 'var(--bg)', border: 'none', cursor: 'pointer', fontWeight: 700 }}>+ ADD FINDING</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
