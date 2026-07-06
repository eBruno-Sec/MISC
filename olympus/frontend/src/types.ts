export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type MissionMode = 'passive' | 'active' | 'full'
export type LogLevel = 'info' | 'warn' | 'error' | 'success'
export type FindingTag = 'confirmed' | 'false_positive' | 'reported' | 'fixed' | null

export type MissionStatus =
  | 'pending' | 'planning' | 'recon' | 'scanning'
  | 'exploiting' | 'post_exploit' | 'reporting'
  | 'complete' | 'awaiting_approval' | 'failed'

export interface Finding {
  id: string
  title: string
  severity: Severity
  description: string | null
  evidence: string | null
  cvss_score: number | null
  remediation: string | null
  found_by: string | null
  tag: FindingTag
  is_manual: boolean
  analyst_notes: string | null
  timestamp: string
}

export interface LogEntry {
  id: string
  agent: string
  symbol: string
  level: LogLevel
  message: string
  timestamp: string
}

export interface ApprovalRequest {
  id: string
  agent: string
  action: string
  description: string | null
  created_at: string
}

export interface MissionNote {
  id: string
  content: string
  timestamp: string
}

export interface LiveHost {
  host: string
  url: string
  status_code: number | null
  server: string
  manually_added?: boolean
}

export interface Mission {
  id: string
  target: string
  scope: string
  mode: MissionMode
  status: MissionStatus
  current_phase: string | null
  scope_rules: { in_scope: ScopeRule[]; out_of_scope: ScopeRule[] } | null
  created_at: string
  completed_at: string | null
  findings: Finding[]
  logs: LogEntry[]
  pending_approvals: ApprovalRequest[]
  notes: MissionNote[]
  context: Record<string, any>
}

export interface MissionSummary {
  id: string
  target: string
  mode: MissionMode
  status: MissionStatus
  current_phase: string | null
  created_at: string
  completed_at: string | null
}

export interface ScopeRule {
  identifier: string
  type: string
}

export interface ParsedScope {
  in_scope: ScopeRule[]
  out_of_scope: ScopeRule[]
  format_detected: string
  total_in: number
  total_out: number
}

export type WSEvent =
  | { type: 'log'; agent: string; symbol: string; display_name: string; level: LogLevel; message: string; timestamp: string }
  | { type: 'finding'; severity: Severity; title: string; found_by: string; display_name: string; timestamp: string }
  | { type: 'finding_updated'; finding_id: string; tag: FindingTag; severity: Severity; timestamp: string }
  | { type: 'finding_deleted'; finding_id: string }
  | { type: 'status_change'; status: MissionStatus; phase: string | null; timestamp: string }
  | { type: 'approval_required'; approval_id: string; agent: string; display_name: string; symbol: string; action: string; description: string; timestamp: string }
  | { type: 'approval_resolved'; approval_id: string; approved: boolean; timestamp: string }
  | { type: 'mission_complete'; report_path: string; stats: Record<Severity, number>; timestamp: string }
  | { type: 'mission_failed'; error: string; timestamp: string }
  | { type: 'agent_rerun'; agent: string; symbol: string; timestamp: string }
  | { type: 'targets_added'; targets: string[]; timestamp: string }
  | { type: 'note_added'; note: MissionNote }

// ── Wordlists ────────────────────────────────────────────────
export type WordlistKind = 'curated' | 'generated'

export interface Wordlist {
  id: string
  name: string
  category: string
  source: string
  desc: string
  kind: WordlistKind
  path: string
  exists: boolean
  count: number
  size: number
}

export interface WordlistCatalog {
  wordlists: Wordlist[]
  default_content_ids: string[]
  total: number
  available: number
}

// ── Oracle (PortSwigger lab solver) ──────────────────────────
export interface OraclePayload {
  label: string
  value: string
}

export interface OraclePlan {
  vulnerability: string
  summary: string
  difficulty: string
  steps: string[]
  payloads: OraclePayload[]
  request: string | null
  success_indicator: string
  notes: string
  raw?: string
}

export interface OracleAI {
  provider: string
  model: string
  configured: boolean
}

export interface OracleResponse {
  plan: OraclePlan
  ai: OracleAI
}
