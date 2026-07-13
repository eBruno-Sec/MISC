import type { Mission, MissionSummary, MissionMode, ParsedScope, Severity, Finding, BackupSummary, HttpExchange, ReplayResult, FuzzResult, AccessCheckResult } from './types'

const BASE = '/api'

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res.json()
}

export const api = {
  // Missions
  listMissions: () => req<MissionSummary[]>('/missions'),
  getMission: (id: string) => req<Mission>(`/missions/${id}`),
  createMission: (target: string, mode: MissionMode, scope: string, scope_rules?: object) =>
    req<{ id: string; target: string; status: string }>('/missions', {
      method: 'POST',
      body: JSON.stringify({ target, mode, scope, scope_rules: scope_rules ?? {} }),
    }),
  deleteMission: (id: string) =>
    req<{ deleted: boolean }>(`/missions/${id}`, { method: 'DELETE' }),
  relaunchMission: (id: string) =>
    req<{ id: string; target: string; status: string; relaunched_from: string }>(
      `/missions/${id}/relaunch`,
      { method: 'POST' }
    ),

  // Approvals
  resolveApproval: (missionId: string, approvalId: string, approved: boolean) =>
    req<{ status: string; approved: boolean; detail?: string }>(
      `/missions/${missionId}/approvals/${approvalId}/resolve`,
      { method: 'POST', body: JSON.stringify({ approved }) }
    ),

  // Findings
  addFinding: (missionId: string, data: {
    title: string; severity: Severity; description?: string;
    evidence?: string; cvss_score?: number; remediation?: string;
  }) =>
    req(`/missions/${missionId}/findings`, { method: 'POST', body: JSON.stringify(data) }),

  updateFinding: (missionId: string, findingId: string, data: Partial<Finding>) =>
    req(`/missions/${missionId}/findings/${findingId}`, {
      method: 'PATCH', body: JSON.stringify(data),
    }),

  deleteFinding: (missionId: string, findingId: string) =>
    req(`/missions/${missionId}/findings/${findingId}`, { method: 'DELETE' }),

  // Targets
  addTargets: (missionId: string, targets: string[], runScan: boolean) =>
    req(`/missions/${missionId}/targets`, {
      method: 'POST',
      body: JSON.stringify({ targets, run_scan: runScan }),
    }),

  // Agent re-run
  rerunAgent: (missionId: string, agent: string, targets?: string[], options?: object) =>
    req(`/missions/${missionId}/agents/${agent}/run`, {
      method: 'POST',
      body: JSON.stringify({ targets: targets ?? null, options: options ?? {} }),
    }),

  // Notes
  addNote: (missionId: string, content: string) =>
    req(`/missions/${missionId}/notes`, {
      method: 'POST', body: JSON.stringify({ content }),
    }),
  deleteNote: (missionId: string, noteId: string) =>
    req(`/missions/${missionId}/notes/${noteId}`, { method: 'DELETE' }),

  // Workbench + evidence
  listHttpExchanges: (missionId: string) =>
    req<HttpExchange[]>(`/missions/${missionId}/http-exchanges`),
  getHttpExchangePoc: (missionId: string, exchangeId: string) =>
    req<{ markdown: string }>(`/missions/${missionId}/http-exchanges/${exchangeId}/poc`),
  replayRequest: (missionId: string, data: {
    method: string; url: string; headers?: Record<string, string>; body?: string | null; timeout?: number;
  }) =>
    req<ReplayResult>(`/missions/${missionId}/replay`, {
      method: 'POST', body: JSON.stringify(data),
    }),
  fuzzRequest: (missionId: string, data: {
    method: string; url: string; parameter: string; payloads: string[]; headers?: Record<string, string>; timeout?: number;
  }) =>
    req<FuzzResult>(`/missions/${missionId}/fuzz`, {
      method: 'POST', body: JSON.stringify(data),
    }),
  accessCheck: (missionId: string, data: {
    method: string; url: string; high_priv_headers?: Record<string, string>; low_priv_headers?: Record<string, string>; body?: string | null; timeout?: number;
  }) =>
    req<AccessCheckResult>(`/missions/${missionId}/access-check`, {
      method: 'POST', body: JSON.stringify(data),
    }),

  // Export
  exportUrl: (missionId: string, format: 'csv' | 'json') =>
    `${BASE}/missions/${missionId}/export?format=${format}`,
  backupUrl: (missionId: string) => `${BASE}/missions/${missionId}/backup`,
  summarizeBackup: (payload: object) =>
    req<BackupSummary>('/missions/backup/summary', {
      method: 'POST',
      body: JSON.stringify({ payload }),
    }),
  importBackup: (payload: object) =>
    req<{ id: string; target: string; status: string; imported_from: string }>(
      '/missions/backup/import',
      { method: 'POST', body: JSON.stringify({ payload }) }
    ),

  // Report + scope parse
  getReportUrl: (missionId: string) => `${BASE}/missions/${missionId}/report`,
  parseScope: async (input: File | string): Promise<ParsedScope> => {
    const form = new FormData()
    if (typeof input === 'string') form.append('text', input)
    else form.append('file', input)
    const res = await fetch(`${BASE}/scope/parse`, { method: 'POST', body: form })
    if (!res.ok) throw new Error('Scope parse failed')
    return res.json()
  },
}
