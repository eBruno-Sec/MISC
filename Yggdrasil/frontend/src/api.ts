import type {
  Mission, MissionSummary, MissionMode, ParsedScope, Severity, Finding,
  WordlistCatalog, Wordlist, OracleResponse, OracleAI, SurfaceInventory,
  ReplayResult, FuzzResult, AuthProfile, AccessResult,
} from './types'

const BASE = '/api'

// Optional API key. When YGGDRASIL_API_KEY is enabled server-side, set it once in
// the browser: localStorage.setItem('yggdrasil_api_key', '<key>'). Legacy
// olympus_api_key is still read as a fallback. With no key set (the localhost
// default) this returns {} and request behavior is unchanged.
function authHeaders(): Record<string, string> {
  const k = typeof localStorage !== 'undefined'
    ? (localStorage.getItem('yggdrasil_api_key') || localStorage.getItem('olympus_api_key') || '')
    : ''
  return k ? { 'X-API-Key': k } : {}
}

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
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
  createMission: (target: string, mode: MissionMode, scope: string, scope_rules?: object, autoApprove = false) =>
    req<{ id: string; target: string; status: string }>('/missions', {
      method: 'POST',
      body: JSON.stringify({ target, mode, scope, scope_rules: scope_rules ?? {}, auto_approve: autoApprove }),
    }),
  relaunchMission: (id: string) =>
    req<{ id: string; target: string; status: string; relaunched_from: string }>(`/missions/${id}/relaunch`, { method: 'POST' }),
  deleteMission: (id: string) =>
    req<{ deleted: boolean }>(`/missions/${id}`, { method: 'DELETE' }),

  // Restore a mission from a Download-Progress (.json) backup. Server re-validates
  // and imports as a NEW mission (fresh id); a 4xx surfaces as the import banner.
  restoreSession: (backup: unknown) =>
    req<{ id: string; target: string; status: string; restored: { findings: number; notes: number; logs: number } }>(
      '/missions/restore', { method: 'POST', body: JSON.stringify(backup) }
    ),

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

  // Attack surface inventory
  getSurface: (missionId: string) => req<SurfaceInventory>(`/missions/${missionId}/surface`),

  // Request workbench (Repeater + Intruder)
  replay: (missionId: string, body: {
    method: string; url: string; headers?: Record<string, string>;
    body?: string | null; follow_redirects?: boolean; save?: boolean;
  }) => req<ReplayResult>(`/missions/${missionId}/replay`, { method: 'POST', body: JSON.stringify(body) }),

  fuzz: (missionId: string, body: {
    method: string; url: string; headers?: Record<string, string>; body?: string | null;
    param: string; param_in: string; payloads?: string[]; wordlist_id?: string; max_payloads?: number;
  }) => req<FuzzResult>(`/missions/${missionId}/fuzz`, { method: 'POST', body: JSON.stringify(body) }),

  // Cross-role access control
  listProfiles: (missionId: string) =>
    req<{ profiles: AuthProfile[]; total: number }>(`/missions/${missionId}/profiles`),
  createProfile: (missionId: string, body: { name: string; role?: string; headers: Record<string, string> }) =>
    req<AuthProfile>(`/missions/${missionId}/profiles`, { method: 'POST', body: JSON.stringify(body) }),
  deleteProfile: (missionId: string, profileId: string) =>
    req<{ deleted: string }>(`/missions/${missionId}/profiles/${profileId}`, { method: 'DELETE' }),
  accessCheck: (missionId: string, body: {
    method: string; url: string; profile_ids: string[];
    owner_profile_id?: string; include_anon?: boolean;
  }) => req<AccessResult>(`/missions/${missionId}/access-check`, { method: 'POST', body: JSON.stringify(body) }),

  // Report + scope parse
  getReportUrl: (missionId: string) => `${BASE}/missions/${missionId}/report`,
  parseScope: async (input: File | string): Promise<ParsedScope> => {
    const form = new FormData()
    if (typeof input === 'string') form.append('text', input)
    else form.append('file', input)
    const res = await fetch(`${BASE}/scope/parse`, { method: 'POST', body: form, headers: authHeaders() })
    if (!res.ok) throw new Error('Scope parse failed')
    return res.json()
  },

  // Wordlists
  listWordlists: () => req<WordlistCatalog>('/wordlists'),
  generateWordlist: (missionId: string, extraPaths: string[] = []) =>
    req<{ generated: Wordlist }>(`/wordlists/generate/${missionId}`, {
      method: 'POST', body: JSON.stringify({ extra_paths: extraPaths }),
    }),
  wordlistPreviewUrl: (id: string, lines = 50) =>
    `${BASE}/wordlists/${encodeURIComponent(id)}/preview?lines=${lines}`,
  wordlistDownloadUrl: (id: string) =>
    `${BASE}/wordlists/${encodeURIComponent(id)}/download`,
  previewWordlist: async (id: string, lines = 50): Promise<string> => {
    const res = await fetch(`${BASE}/wordlists/${encodeURIComponent(id)}/preview?lines=${lines}`, { headers: authHeaders() })
    if (!res.ok) throw new Error('Preview failed')
    return res.text()
  },

  // Oracle (PortSwigger lab solver)
  oracleStatus: () => req<OracleAI>('/oracle/status'),
  oracleSolve: (body: {
    lab_title?: string; description?: string; lab_url?: string;
    category?: string; captured_request?: string; captured_response?: string;
  }) => req<OracleResponse>('/oracle/solve', { method: 'POST', body: JSON.stringify(body) }),
  oracleFollowup: (body: {
    lab_title?: string; description?: string; prior?: object;
    what_happened?: string; captured_response?: string;
  }) => req<OracleResponse>('/oracle/followup', { method: 'POST', body: JSON.stringify(body) }),
}
