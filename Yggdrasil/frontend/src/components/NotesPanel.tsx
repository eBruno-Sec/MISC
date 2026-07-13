import { useState } from 'react'
import { api } from '../api'
import type { MissionNote } from '../types'

interface Props {
  missionId: string
  notes: MissionNote[]
  onDelete: (id: string) => void
}

export default function NotesPanel({ missionId, notes, onDelete }: Props) {
  const [input, setInput] = useState('')
  const [saving, setSaving] = useState(false)

  const save = async () => {
    if (!input.trim()) return
    setSaving(true)
    try {
      await api.addNote(missionId, input.trim())
      setInput('')
    } catch (e: any) {
      alert(e.message)
    } finally {
      setSaving(false)
    }
  }

  const del = async (id: string) => {
    try {
      await api.deleteNote(missionId, id)
      onDelete(id)
    } catch {}
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        padding: '0.6rem 1rem', background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        fontSize: '0.65rem', letterSpacing: '0.2em', color: 'var(--text-dim)',
      }}>
        ANALYST NOTES ({notes.length})
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '0.75rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {notes.length === 0 && (
          <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', textAlign: 'center', paddingTop: '2rem' }}>
            No notes yet. Add observations, hypotheses, or anything useful.
          </div>
        )}
        {[...notes].reverse().map(n => (
          <div key={n.id} style={{
            background: 'var(--surface2)', border: '1px solid var(--border)',
            padding: '0.75rem 1rem',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)' }}>
                {new Date(n.timestamp).toLocaleString()}
              </span>
              <button
                onClick={() => del(n.id)}
                style={{ fontSize: '0.7rem', color: 'var(--text-dim)', cursor: 'pointer' }}
                title="Delete note"
              >✕</button>
            </div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text)', lineHeight: 1.8, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {n.content}
            </div>
          </div>
        ))}
      </div>

      <div style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) save() }}
          placeholder="Observation, hypothesis, next step... (Ctrl+Enter to save)"
          rows={3}
          style={{ width: '100%', resize: 'none', fontSize: '0.82rem', marginBottom: '0.5rem' }}
        />
        <button
          onClick={save}
          disabled={saving || !input.trim()}
          style={{
            fontSize: '0.72rem', letterSpacing: '0.15em',
            padding: '0.35rem 0.9rem', float: 'right',
            background: saving ? 'var(--accent-dim)' : 'var(--accent)',
            color: saving ? 'var(--accent)' : 'var(--bg)',
            border: '1px solid var(--accent)', cursor: 'pointer',
          }}
        >
          {saving ? 'SAVING...' : '+ NOTE'}
        </button>
      </div>
    </div>
  )
}
