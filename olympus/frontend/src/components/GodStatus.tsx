type GodState = 'idle' | 'active' | 'complete' | 'failed'

interface GodDef {
  name: string
  symbol: string
  role: string
  key: string
}

const GODS: GodDef[] = [
  { key: 'zeus', name: 'ZEUS', symbol: '⚡', role: 'Orchestrator' },
  { key: 'athena', name: 'ATHENA', symbol: '🦉', role: 'AI Strategy' },
  { key: 'hermes', name: 'HERMES', symbol: '☿', role: 'OSINT / Recon' },
  { key: 'ares', name: 'ARES', symbol: '⚔', role: 'Active Scanning' },
  { key: 'hephaestus', name: 'HEPHAESTUS', symbol: '🔥', role: 'Payload Forge' },
  { key: 'hades', name: 'HADES', symbol: '💀', role: 'Post-Exploit' },
  { key: 'apollo', name: 'APOLLO', symbol: '☀', role: 'Reporting' },
]

interface Props {
  currentPhase: string | null
  status: string
  completedPhases: Set<string>
}

function godState(key: string, currentPhase: string | null, missionStatus: string, completedPhases: Set<string>): GodState {
  if (missionStatus === 'failed') return completedPhases.has(key) ? 'complete' : 'idle'
  if (completedPhases.has(key)) return 'complete'
  if (currentPhase === key) return 'active'
  return 'idle'
}

export default function GodStatus({ currentPhase, status, completedPhases }: Props) {
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)',
      gap: '1px', background: 'var(--border)',
    }}>
      {GODS.map(g => {
        const state = godState(g.key, currentPhase, status, completedPhases)
        const color = state === 'active' ? 'var(--accent)'
          : state === 'complete' ? 'var(--accent3)'
          : state === 'failed' ? 'var(--crit)'
          : 'var(--text-dim)'

        return (
          <div key={g.key} style={{
            background: state === 'active' ? 'rgba(0,229,255,0.05)' : 'var(--surface)',
            padding: '1rem 0.75rem',
            borderBottom: `2px solid ${state === 'idle' ? 'transparent' : color}`,
            textAlign: 'center',
            transition: 'all 0.25s',
          }}>
            <div style={{
              fontSize: '1.4rem', marginBottom: '0.35rem',
              filter: state === 'active' ? `drop-shadow(0 0 8px ${color})` : 'none',
              animation: state === 'active' ? 'pulse-border 2s ease infinite' : 'none',
            }}>
              {g.symbol}
            </div>
            <div style={{ fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.12em', color, marginBottom: '0.2rem' }}>
              {g.name}
            </div>
            <div style={{ fontSize: '0.6rem', color: 'var(--text-dim)', lineHeight: 1.3 }}>
              {g.role}
            </div>
            <div style={{ marginTop: '0.4rem', fontSize: '0.58rem', letterSpacing: '0.1em', color }}>
              {state === 'active' && '● RUNNING'}
              {state === 'complete' && '✓ DONE'}
              {state === 'idle' && '○ IDLE'}
              {state === 'failed' && '✕ ERR'}
            </div>
          </div>
        )
      })}
    </div>
  )
}
