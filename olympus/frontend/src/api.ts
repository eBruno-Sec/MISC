import type { Mission, MissionSummary, MissionMode, ParsedScope, FindingTag, Severity, Finding } from './types'

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

  // Approvals
  resolveApproval: (missionId: string, approvalId: string, approved: boolean) =>
    req<{ status: string; approved: boolean }>(
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

  // Export
  exportUrl: (missionId: string, format: 'csv' | 'json') =>
    `${BASE}/missions/${missionId}/export?format=${format}`,

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
