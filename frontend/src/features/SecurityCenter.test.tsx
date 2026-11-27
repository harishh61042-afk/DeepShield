import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const apiMock = vi.hoisted(() => ({
  me: vi.fn(), projects: vi.fn(), scans: vi.fn(), sboms: vi.fn(), importSbom: vi.fn(), compareSboms: vi.fn(),
  sbomVulnerabilities: vi.fn(), securityPolicy: vi.fn(), updateSecurityPolicy: vi.fn(), evaluatePolicy: vi.fn(),
  remediation: vi.fn(), licenseInventory: vi.fn(), refreshLicenses: vi.fn(), monitoringSchedule: vi.fn(),
  saveMonitoringSchedule: vi.fn(), deleteMonitoringSchedule: vi.fn(), notifications: vi.fn(),
  markNotificationRead: vi.fn(), markAllNotificationsRead: vi.fn(), notificationPreferences: vi.fn(),
  saveNotificationPreferences: vi.fn(),
}))

vi.mock('../api/client', () => ({ api: apiMock }))

import { SecurityCenterPage } from './SecurityCenter'

const user = { id: 'user-1', email: 'owner@example.com', display_name: 'Owner', role: 'developer' as const, created_at: '2026-01-01T00:00:00Z' }
const project = { id: 'project-1', name: 'Demo', description: '', ecosystem: 'javascript', owner_id: user.id, archived: false, created_at: '2026-01-01T00:00:00Z', latest_scan: null }
const scan = { id: 'scan-1', project_id: project.id, status: 'completed', stage: 'Completed', source_filename: 'package-lock.json', source_bytes: 20, created_at: '2026-01-02T00:00:00Z', started_at: null, completed_at: '2026-01-02T00:00:00Z', intelligence_status: {}, error_message: null }
const policy = { project_id: project.id, max_allowed_priority: 'High' as const, fail_on_kev: true, partial_behavior: 'warning' as const, unavailable_behavior: 'warning' as const, fail_on_unknown_license: false, allowed_licenses: [], restricted_licenses: [] }
const sboms = { imported: [{ id: 'sbom-1', filename: 'imported.cdx.json', spec_version: '1.6', created_at: '2026-01-02T00:00:00Z', component_count: 1 }], generated: [{ id: scan.id, filename: scan.source_filename, status: scan.status, created_at: scan.created_at, component_count: 1 }] }

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><SecurityCenterPage /></MemoryRouter></QueryClientProvider>)
}

beforeEach(() => {
  vi.clearAllMocks()
  apiMock.me.mockResolvedValue({ user })
  apiMock.projects.mockResolvedValue({ items: [project] })
  apiMock.scans.mockResolvedValue({ items: [scan] })
  apiMock.sboms.mockResolvedValue(sboms)
  apiMock.importSbom.mockResolvedValue({ id: 'sbom-new', filename: 'new.json', component_count: 1 })
  apiMock.compareSboms.mockResolvedValue({ left: { kind: 'imported', id: 'sbom-1', filename: 'a' }, right: { kind: 'generated', id: 'scan-1', filename: 'b' }, added: [], removed: [], changed: [], counts: { added: 0, removed: 0, changed: 0 }, notes: [] })
  apiMock.sbomVulnerabilities.mockResolvedValue({ status: 'available', items: [], note: 'OSV evidence only.' })
  apiMock.securityPolicy.mockResolvedValue(policy)
  apiMock.updateSecurityPolicy.mockImplementation(async (_id, input) => ({ ...input, project_id: project.id }))
  apiMock.evaluatePolicy.mockResolvedValue({ status: 'WARNING', scan_id: scan.id, project_id: project.id, checks: [], failures: [], warnings: ['Partial scan'] })
  apiMock.remediation.mockResolvedValue({ scan_id: scan.id, status: 'completed', groups: { urgent: [], high: [], routine: [], needs_evidence: [] }, limitations: [] })
  apiMock.licenseInventory.mockResolvedValue({ project_id: project.id, scan_id: scan.id, scan_status: 'completed', items: [], evaluation: { status: 'clear', violations: [], unknown: [], disclaimer: 'Not legal advice.' }, policy: { allowed_licenses: [], restricted_licenses: [], fail_on_unknown_license: false } })
  apiMock.refreshLicenses.mockResolvedValue({ checked: 1, deferred_or_cached: 0, items: [] })
  apiMock.monitoringSchedule.mockResolvedValue({ project_id: project.id, configured: false, active: false })
  apiMock.saveMonitoringSchedule.mockResolvedValue({ project_id: project.id, configured: true, interval_hours: 24, active: true, next_run_at: '2026-01-03T00:00:00Z' })
  apiMock.deleteMonitoringSchedule.mockResolvedValue({ configured: false })
  apiMock.notifications.mockResolvedValue({ items: [{ id: 'notification-1', project_id: project.id, event_type: 'new_vulnerability', title: 'New issue', message: 'Review package.', payload: {}, read_at: null, email_status: 'not_requested', created_at: '2026-01-02T00:00:00Z' }] })
  apiMock.markNotificationRead.mockResolvedValue({ id: 'notification-1', read_at: '2026-01-03T00:00:00Z' })
  apiMock.markAllNotificationsRead.mockResolvedValue({ updated: 1 })
  apiMock.notificationPreferences.mockResolvedValue({ email_enabled: false, smtp_configured: true })
  apiMock.saveNotificationPreferences.mockResolvedValue({ email_enabled: true, smtp_configured: true })
})

describe('Security center', () => {
  it('connects SBOM import, comparison, OSV lookup, project policy, remediation, licenses, monitoring and alerts to API actions', async () => {
    renderPage()

    const uploadInput = await screen.findByLabelText('CycloneDX JSON')
    fireEvent.change(uploadInput, { target: { files: [new File(['{}'], 'sample.cdx.json', { type: 'application/json' })] } })
    fireEvent.click(screen.getByRole('button', { name: 'Import SBOM' }))
    await waitFor(() => expect(apiMock.importSbom).toHaveBeenCalledWith(project.id, expect.any(File)))

    fireEvent.change(screen.getByLabelText('From'), { target: { value: 'imported:sbom-1' } })
    fireEvent.change(screen.getByLabelText('To'), { target: { value: 'generated:scan-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }))
    await waitFor(() => expect(apiMock.compareSboms).toHaveBeenCalled())
    fireEvent.change(screen.getByLabelText('Imported SBOM'), { target: { value: 'sbom-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check vulnerabilities' }))
    await waitFor(() => expect(apiMock.sbomVulnerabilities).toHaveBeenCalledWith(project.id, 'sbom-1'))

    fireEvent.click(screen.getByRole('tab', { name: 'Security policies' }))
    await screen.findByRole('button', { name: 'Save project policy' })
    fireEvent.click(screen.getByRole('button', { name: 'Save project policy' }))
    await waitFor(() => expect(apiMock.updateSecurityPolicy).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate policy' }))
    await waitFor(() => expect(apiMock.evaluatePolicy).toHaveBeenCalledWith(scan.id))
    expect(await screen.findByText('WARNING')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: 'Remediation' }))
    await waitFor(() => expect(apiMock.remediation).toHaveBeenCalledWith(scan.id, false))

    fireEvent.click(screen.getByRole('tab', { name: 'License compliance' }))
    await screen.findByRole('button', { name: /Refresh package metadata/ })
    fireEvent.click(screen.getByRole('button', { name: /Refresh package metadata/ }))
    await waitFor(() => expect(apiMock.refreshLicenses).toHaveBeenCalledWith(project.id))

    fireEvent.click(screen.getByRole('tab', { name: 'Monitoring' }))
    await screen.findByRole('button', { name: 'Create schedule' })
    fireEvent.click(screen.getByRole('button', { name: 'Create schedule' }))
    await waitFor(() => expect(apiMock.saveMonitoringSchedule).toHaveBeenCalledWith(project.id, 24, true))

    fireEvent.click(screen.getByRole('tab', { name: 'Alerts' }))
    await screen.findByText('New issue')
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(apiMock.markAllNotificationsRead).toHaveBeenCalled())
    fireEvent.click(screen.getByLabelText(/Email alerts/))
    await waitFor(() => expect(apiMock.saveNotificationPreferences).toHaveBeenCalledWith(true))
  })
})
