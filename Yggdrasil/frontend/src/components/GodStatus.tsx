type GodState = 'idle' | 'active' | 'complete' | 'failed'

interface GodDef {
  name: string
  symbol: string
  role: string
  key: string
}

const GODS: GodDef[] = [
  { key: 'zeus',        name: 'ZEUS',       symbol: 'Z',  role: 'Orchestrator' },
  { key: 'athena',      name: 'ATHENA',     symbol: 'AT', role: 'AI Strategy' },
  { key: 'hermes',      name: 'HERMES',     symbol: 'HE', role: 'OSINT / Recon' },
  { key: 'ares',        name: 'ARES',       symbol: 'AR', role: 'Active Scanning' },
  { key: 'hephaestus',  name: 'HEPHAESTUS', symbol: 'HF', role: 'Payload Forge' },
  { key: 'hades',       name: 'HADES',      symbol: 'HD', role: 'Post-Exploit' },
  { key: 'apollo',      name: 'APOLLO',     symbol: 'AP', role: 'Reporting' },
]

const RERUNNABLE = new Set(['hermes', 'ares', 'hephaestus', 'hades', 'apollo', 'athena'])

interface Props {
  currentPhase: string | null
  status: string
  completedPhases: Set<string>
  onRerun?: (god: GodDef) => void
}

function godState(key: string, currentPhase: string | null, missionStatus: string, completedPhases: Set<string>): GodState {
  if (missionStatus === 'failed') return completedPhases.has(key) ? 'complete' : 'idle'
  if (completedPhases.has(key)) return 'complete'
  if (currentPhase === key) return 'active'
  return 'idle'
}

export default function GodStatus({ currentPhase, status, completedPhases, onRerun }: Props) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '1px', background: 'var(--border)' }}>
      {GODS.map(g => {
        const state = godState(g.key, currentPhase, status, completedPhases)
        const color = state === 'active' ? 'var(--accent)'
          : state === 'complete' ? 'var(--accent3)'
          : state === 'failed' ? 'var(--crit)'
          : 'var(--text-dim)'
        const canRerun = state === 'complete' && RERUNNABLE.has(g.key) && !!onRerun

        return (
          <div
            key={g.key}
            title={canRerun ? `Re-run ${g.name}` : undefined}
            onClick={canRerun ? () => onRerun!(g) : undefined}
            style={{
              background: state === 'active' ? 'rgba(0,229,255,0.05)' : 'var(--surface)',
              padding: '0.85rem 0.5rem',
              borderBottom: `2px solid ${state === 'idle' ? 'transparent' : color}`,
              textAlign: 'center',
              transition: 'all 0.2s',
              cursor: canRerun ? 'pointer' : 'default',
              position: 'relative',
            }}
            onMouseEnter={canRerun ? e => { e.currentTarget.style.background = 'rgba(57,255,20,0.05)' } : undefined}
            onMouseLeave={canRerun ? e => { e.currentTarget.style.background = 'var(--surface)' } : undefined}
          >
            <div style={{
              fontSize: '1.3rem', marginBottom: '0.3rem',
              filter: state === 'active' ? `drop-shadow(0 0 8px ${color})` : 'none',
              animation: state === 'active' ? 'pulse-border 2s ease infinite' : 'none',
            }}>
              {g.symbol}
            </div>
            <div style={{ fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.1em', color, marginBottom: '0.15rem' }}>
              {g.name}
            </div>
            <div style={{ fontSize: '0.55rem', color: 'var(--text-dim)', lineHeight: 1.3 }}>{g.role}</div>
            <div style={{ marginTop: '0.35rem', fontSize: '0.55rem', letterSpacing: '0.08em', color }}>
              {state === 'active'   && 'RUNNING'}
              {state === 'complete' && (canRerun ? 'RE-RUN' : 'DONE')}
              {state === 'idle'     && 'IDLE'}
              {state === 'failed'   && 'ERR'}
            </div>
          </div>
        )
      })}
    </div>
  )
}
