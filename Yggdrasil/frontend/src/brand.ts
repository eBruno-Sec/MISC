export const PRODUCT_NAME = 'Yggdrasil'
export const PRODUCT_TAGLINE = 'Authorized security assessment workspace'

export interface AgentDef {
  key: string
  name: string
  symbol: string
  role: string
  tint: string
}

export const AGENTS: AgentDef[] = [
  { key: 'zeus', name: 'ODIN', symbol: 'OD', role: 'Orchestration', tint: 'var(--accent)' },
  { key: 'athena', name: 'FRIGG', symbol: 'FR', role: 'Strategy', tint: '#6b6fb4' },
  { key: 'hermes', name: 'HEIMDALL', symbol: 'HE', role: 'Recon', tint: '#3b7f8f' },
  { key: 'ares', name: 'TYR', symbol: 'TY', role: 'Active Assessment', tint: 'var(--accent2)' },
  { key: 'hephaestus', name: 'BROKKR', symbol: 'BR', role: 'Payload Forge', tint: 'var(--gold)' },
  { key: 'hades', name: 'SKULD', symbol: 'SK', role: 'Impact Review', tint: '#6f7380' },
  { key: 'metis', name: 'MIMIR', symbol: 'MI', role: 'Triage', tint: '#7a66a3' },
  { key: 'apollo', name: 'SAGA', symbol: 'SA', role: 'Reporting', tint: 'var(--accent3)' },
]

export const AGENT_ORDER = AGENTS.map(agent => agent.key)

const AGENT_BY_KEY = Object.fromEntries(AGENTS.map(agent => [agent.key, agent]))

export function agentMeta(key: string | null | undefined): AgentDef {
  if (key && AGENT_BY_KEY[key]) return AGENT_BY_KEY[key]
  const label = (key || 'agent').toUpperCase()
  return {
    key: key || 'agent',
    name: label,
    symbol: label.slice(0, 2),
    role: 'Assessment Stage',
    tint: 'var(--text-dim)',
  }
}
