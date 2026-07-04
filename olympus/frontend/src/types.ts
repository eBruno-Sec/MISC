export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type MissionMode = 'passive' | 'active' | 'full'
export type LogLevel = 'info' | 'warn' | 'error' | 'success'

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

export interface Mission {
  id: string
  target: string
  scope: string
  mode: MissionMode
  status: MissionStatus
  current_phase: string | null
  created_at: string
  completed_at: string | null
  findings: Finding[]
  logs: LogEntry[]
  pending_approvals: ApprovalRequest[]
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

// WebSocket event types
export type WSEvent =
  | { type: 'log'; agent: string; symbol: string; display_name: string; level: LogLevel; message: string; timestamp: string }
  | { type: 'finding'; severity: Severity; title: string; found_by: string; display_name: string; timestamp: string }
  | { type: 'status_change'; status: MissionStatus; phase: string | null; timestamp: string }
  | { type: 'approval_required'; approval_id: string; agent: string; display_name: string; symbol: string; action: string; description: string; timestamp: string }
  | { type: 'approval_resolved'; approval_id: string; approved: boolean; timestamp: string }
  | { type: 'mission_complete'; report_path: string; stats: Record<Severity, number>; timestamp: string }
  | { type: 'mission_failed'; error: string; timestamp: string }
