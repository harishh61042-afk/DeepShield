import type { Component, Finding, LicenseInventory, MonitoringSchedule, PolicyEvaluation, Project, RemediationPlan, SBOMDiff, SBOMItem, SecurityPolicy, Scan, User, UserNotification } from '../types'

const API = '/api/v1'
let csrf: string | null = null

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) { super(message); this.status = status }
}

function readableDetail(detail: unknown, fallback: string): string {
  if (typeof detail === 'string' && detail.trim()) return detail
  if (detail && typeof detail === 'object' && 'message' in detail && typeof detail.message === 'string') return detail.message
  if (Array.isArray(detail)) {
    const messages = detail.flatMap(item => item && typeof item === 'object' && 'msg' in item && typeof item.msg === 'string' ? [item.msg] : [])
    if (messages.length) return messages.join('; ')
  }
  return fallback
}

async function csrfToken() {
  if (!csrf) {
    const response = await fetch(`${API}/auth/csrf`, { credentials: 'include' })
    const body = await response.json()
    if (!response.ok || typeof body?.csrf_token !== 'string') throw new ApiError(readableDetail(body?.detail, 'Could not initialize request protection'), response.status)
    csrf = body.csrf_token
  }
  return csrf
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  return performRequest<T>(path, init, true)
}

async function performRequest<T>(path: string, init: RequestInit, retryCsrf: boolean): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (!(init.body instanceof FormData) && init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) headers.set('X-CSRF-Token', (await csrfToken()) ?? '')
  const response = await fetch(`${API}${path}`, { ...init, method, headers, credentials: 'include' })
  const body = response.status === 204 ? null : await response.json().catch(() => null)
  if (!response.ok) {
    if (response.status === 401) csrf = null
    if (response.status === 403 && body?.detail === 'CSRF validation failed') {
      csrf = null
      if (retryCsrf) return performRequest<T>(path, init, false)
    }
    throw new ApiError(readableDetail(body?.detail, `Request failed (${response.status})`), response.status)
  }
  if (body?.csrf_token) csrf = body.csrf_token
  if ((method === 'POST' && ['/auth/logout', '/auth/password', '/auth/password-reset/complete'].includes(path)) || (method === 'DELETE' && path === '/auth/account')) csrf = null
  return body as T
}

export const api = {
  me: () => request<{ user: User }>('/auth/me'),
  login: (email: string, password: string) => request<{ user: User }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  register: (display_name: string, email: string, password: string) => request<{ message: string }>('/auth/register', { method: 'POST', body: JSON.stringify({ display_name, email, password, accept_terms: true }) }),
  logout: () => request<{ message: string }>('/auth/logout', { method: 'POST' }),
  resetRequest: (email: string) => request<{ message: string }>('/auth/password-reset', { method: 'POST', body: JSON.stringify({ email }) }),
  resetComplete: (token: string, new_password: string) => request<{ message: string }>('/auth/password-reset/complete', { method: 'POST', body: JSON.stringify({ token, new_password }) }),
  dashboard: () => request<{ projects: number; scans: number; components: number; priority_counts: Record<string, number>; known_exploited_findings: number; recent_scans: Scan[] }>('/dashboard'),
  projects: () => request<{ items: Project[] }>('/projects'),
  createProject: (input: { name: string; description: string; ecosystem: string }) => request<Project>('/projects', { method: 'POST', body: JSON.stringify(input) }),
  updateProject: (id: string, input: Partial<Pick<Project, 'name' | 'description' | 'ecosystem' | 'archived'>>) => request<Project>('/projects/' + id, { method: 'PATCH', body: JSON.stringify(input) }),
  deleteProject: (project: Project) => request<{ message: string }>(`/projects/${project.id}?confirm_name=${encodeURIComponent(project.name)}`, { method: 'DELETE' }),
  scans: (projectId: string) => request<{ items: Scan[] }>(`/projects/${projectId}/scans`),
  members: (projectId: string) => request<{ items: { id: string; user_id: string; email: string; display_name: string; access: string }[] }>(`/projects/${projectId}/members`),
  addMember: (projectId: string, email: string) => request(`/projects/${projectId}/members`, { method: 'POST', body: JSON.stringify({ email }) }),
  removeMember: (projectId: string, memberId: string) => request(`/projects/${projectId}/members/${memberId}`, { method: 'DELETE' }),
  compareScans: (newerId: string, olderId: string) => request<{ comparison_reliable: boolean; new_findings: string[]; findings_in_both: string[]; no_longer_detected: string[] | null; note: string | null }>(`/scans/${newerId}/compare/${olderId}`),
  scan: (id: string) => request<Scan & { component_count: number; finding_count: number; priority_counts: Record<string, number> }>(`/scans/${id}`),
  upload: (projectId: string, file: File) => { const form = new FormData(); form.append('file', file); return request<Scan>(`/projects/${projectId}/scans`, { method: 'POST', body: form }) },
  components: (id: string) => request<{ items: Component[] }>(`/scans/${id}/components?limit=500`),
  findings: (id: string, q = '') => request<{ items: Finding[] }>(`/scans/${id}/findings?limit=200&q=${encodeURIComponent(q)}`),
  searchFindings: (q = '') => request<{ items: Finding[] }>(`/vulnerabilities?limit=200&q=${encodeURIComponent(q)}`),
  explain: (id: string) => request<{ explanation: string; potential_impact: string; priority_reasoning: string; remediation: string; uncertainty: string; references: string[]; generated_by: string }>(`/findings/${id}/explanation`, { method: 'POST' }),
  adminUsers: () => request<{ items: (User & { is_active: boolean })[] }>('/admin/users'),
  adminOverview: () => request<Record<string, unknown>>('/admin/overview'),
  adminJobs: () => request<{ items: { id: string; scan_id: string; status: string; attempts: number; max_attempts: number; last_error: string | null; created_at: string }[] }>('/admin/jobs'),
  adminAudit: () => request<{ items: { id: string; actor_id: string | null; action: string; target_type: string; target_id: string; outcome: string; metadata: unknown; created_at: string }[] }>('/admin/audit'),
  adminHealth: () => request<{ database: string; kev_status: string; kev_entries: number | null; ollama: string; worker: string }>('/admin/health'),
  sboms: (projectId: string) => request<{ imported: SBOMItem[]; generated: SBOMItem[] }>(`/projects/${projectId}/sboms`),
  importSbom: (projectId: string, file: File) => { const form = new FormData(); form.append('file', file); return request<SBOMItem>(`/projects/${projectId}/sboms/import`, { method: 'POST', body: form }) },
  compareSboms: (projectId: string, left: { kind: 'imported' | 'generated'; id: string }, right: { kind: 'imported' | 'generated'; id: string }) => request<SBOMDiff>(`/projects/${projectId}/sboms/compare`, { method: 'POST', body: JSON.stringify({ left, right }) }),
  sbomVulnerabilities: (projectId: string, sbomId: string) => request<{ status: string; items: { component: Record<string, unknown>; osv_id: string; summary: string; version_confirmed_installed: boolean }[]; note: string }>(`/projects/${projectId}/sboms/${sbomId}/vulnerabilities`, { method: 'POST' }),
  securityPolicy: (projectId: string) => request<SecurityPolicy>(`/projects/${projectId}/security-policy`),
  updateSecurityPolicy: (projectId: string, input: Omit<SecurityPolicy, 'project_id'>) => request<SecurityPolicy>(`/projects/${projectId}/security-policy`, { method: 'PUT', body: JSON.stringify(input) }),
  evaluatePolicy: (scanId: string) => request<PolicyEvaluation>(`/scans/${scanId}/policy/evaluate`, { method: 'POST' }),
  remediation: (scanId: string, ai = false) => request<RemediationPlan>(`/scans/${scanId}/remediation?ai_explanations=${ai}`),
  licenseInventory: (projectId: string) => request<LicenseInventory>(`/projects/${projectId}/licenses`),
  refreshLicenses: (projectId: string) => request<{ checked: number; deferred_or_cached: number; items: LicenseInventory['items'] }>(`/projects/${projectId}/licenses/refresh`, { method: 'POST' }),
  monitoringSchedule: (projectId: string) => request<MonitoringSchedule>(`/projects/${projectId}/monitoring/schedule`),
  saveMonitoringSchedule: (projectId: string, interval_hours: number, active: boolean) => request<MonitoringSchedule>(`/projects/${projectId}/monitoring/schedule`, { method: 'PUT', body: JSON.stringify({ interval_hours, active }) }),
  deleteMonitoringSchedule: (projectId: string) => request<{ configured: boolean }>(`/projects/${projectId}/monitoring/schedule`, { method: 'DELETE' }),
  notifications: (unread_only = false) => request<{ items: UserNotification[] }>(`/notifications?unread_only=${unread_only}`),
  markNotificationRead: (id: string) => request<{ id: string; read_at: string }>(`/notifications/${id}/read`, { method: 'POST' }),
  markAllNotificationsRead: () => request<{ updated: number }>('/notifications/read-all', { method: 'POST' }),
  notificationPreferences: () => request<{ email_enabled: boolean; smtp_configured: boolean }>('/notification-preferences'),
  saveNotificationPreferences: (email_enabled: boolean) => request<{ email_enabled: boolean; smtp_configured: boolean }>('/notification-preferences', { method: 'PUT', body: JSON.stringify({ email_enabled }) }),
  updateStatus: (id: string, is_active: boolean) => request(`/admin/users/${id}/status`, { method: 'PATCH', body: JSON.stringify({ is_active }) }),
  updateRole: (id: string, role: string) => request(`/admin/users/${id}/role`, { method: 'PATCH', body: JSON.stringify({ role }) }),
  updateProfile: (display_name: string) => request<{ user: User }>('/profile', { method: 'PATCH', body: JSON.stringify({ display_name }) }),
  changePassword: (current_password: string, new_password: string) => request<{ message: string }>('/auth/password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  revokeOtherSessions: () => request<{ revoked: number }>('/auth/sessions/revoke-others', { method: 'POST' }),
  deleteAccount: (password: string) => request<{ message: string }>('/auth/account', { method: 'DELETE', body: JSON.stringify({ password, confirm: true }) }),
}
