import { AGENTS, type AgentDef } from '../brand'

type StageState = 'idle' | 'active' | 'complete' | 'failed'

const RERUNNABLE = new Set(['hermes', 'ares', 'hephaestus', 'hades', 'apollo', 'athena'])

interface Props {
  currentPhase: string | null
  status: string
  completedPhases: Set<string>
  onRerun?: (agent: AgentDef) => void
}

function stageState(key: string, currentPhase: string | null, missionStatus: string, completedPhases: Set<string>): StageState {
  if (missionStatus === 'failed') return completedPhases.has(key) ? 'complete' : 'idle'
  if (completedPhases.has(key)) return 'complete'
  if (currentPhase === key) return 'active'
  return 'idle'
}

export default function GodStatus({ currentPhase, status, completedPhases, onRerun }: Props) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(7, minmax(112px, 1fr))',
      gap: '0.7rem',
      padding: '0.8rem 1rem',
      background: 'var(--surface2)',
      borderBottom: '1px solid var(--border)',
      overflowX: 'auto',
    }}>
      {AGENTS.map(agent => {
        const state = stageState(agent.key, currentPhase, status, completedPhases)
        const color = state === 'active' ? agent.tint
          : state === 'complete' ? 'var(--accent3)'
          : state === 'failed' ? 'var(--crit)'
          : 'var(--text-dim)'
        const canRerun = state === 'complete' && RERUNNABLE.has(agent.key) && !!onRerun

        return (
          <button
            key={agent.key}
            title={canRerun ? `Re-run ${agent.name}` : undefined}
            onClick={canRerun ? () => onRerun!(agent) : undefined}
            style={{
              background: state === 'active' ? 'var(--surface)' : 'rgba(255,255,255,0.72)',
              padding: '0.75rem',
              border: `1px solid ${state === 'idle' ? 'var(--border)' : color}`,
              borderRadius: 'var(--radius)',
              textAlign: 'left',
              transition: 'border-color 0.2s, box-shadow 0.2s, transform 0.2s',
              cursor: canRerun ? 'pointer' : 'default',
              boxShadow: state === 'active' ? '0 10px 24px rgba(47,117,102,0.12)' : 'none',
              transform: state === 'active' ? 'translateY(-1px)' : 'none',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.45rem' }}>
              <span style={{
                width: '2rem',
                height: '2rem',
                borderRadius: '50%',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: `${color}18`,
                color,
                fontWeight: 850,
                fontSize: '0.72rem',
              }}>
                {agent.symbol}
              </span>
              <span style={{ minWidth: 0 }}>
                <span style={{ display: 'block', fontSize: '0.76rem', fontWeight: 850, color: 'var(--text-bright)' }}>
                  {agent.name}
                </span>
                <span style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {agent.role}
                </span>
              </span>
            </div>
            <div style={{ fontSize: '0.68rem', color, fontWeight: 750 }}>
              {state === 'active' && 'Running'}
              {state === 'complete' && (canRerun ? 'Re-run available' : 'Done')}
              {state === 'idle' && 'Idle'}
              {state === 'failed' && 'Needs review'}
            </div>
          </button>
        )
      })}
    </div>
  )
}
