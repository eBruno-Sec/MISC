import type { Mission, MissionSummary, MissionMode } from './types'

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
  listMissions: () => req<MissionSummary[]>('/missions'),

  getMission: (id: string) => req<Mission>(`/missions/${id}`),

  createMission: (target: string, mode: MissionMode, scope: string) =>
    req<{ id: string; target: string; status: string }>('/missions', {
      method: 'POST',
      body: JSON.stringify({ target, mode, scope }),
    }),

  deleteMission: (id: string) =>
    req<{ deleted: boolean }>(`/missions/${id}`, { method: 'DELETE' }),

  resolveApproval: (missionId: string, approvalId: string, approved: boolean) =>
    req<{ status: string; approved: boolean }>(
      `/missions/${missionId}/approvals/${approvalId}/resolve`,
      { method: 'POST', body: JSON.stringify({ approved }) }
    ),

  getReportUrl: (missionId: string) => `${BASE}/missions/${missionId}/report`,
}
