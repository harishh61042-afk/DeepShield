import { useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Bell, Check, Download, FileBox, FileText, RefreshCw, ShieldCheck, TimerReset } from 'lucide-react'
import { api } from '../api/client'
import type { LicenseInventory, MonitoringSchedule, PolicyEvaluation, Project, SBOMDiff, SecurityPolicy } from '../types'

type Tab = 'sbom' | 'policy' | 'remediation' | 'licenses' | 'monitoring' | 'alerts'
type SourceValue = `${'imported' | 'generated'}:${string}`

function downloadJSON(filename: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

function ErrorMessage({ children }: { children: ReactNode }) {
  return <p className="form-alert error security-error" role="alert">{children}</p>
}

function Notice({ children }: { children: ReactNode }) {
  return <p className="form-alert success security-notice" role="status">{children}</p>
}

function Loading({ label }: { label: string }) { return <p className="security-muted" role="status">{label}</p> }

export function SecurityCenterPage() {
  const [tab, setTab] = useState<Tab>('sbom')
  const [requestedProjectId, setRequestedProjectId] = useState('')
  const [scanId, setScanId] = useState('')
  const projectsQuery = useQuery({ queryKey: ['projects'], queryFn: api.projects })
  const projects = projectsQuery.data?.items ?? []
  const projectId = projects.some(item => item.id === requestedProjectId) ? requestedProjectId : (projects[0]?.id ?? '')
  const project = projects.find(item => item.id === projectId)
  const scansQuery = useQuery({ queryKey: ['project-scans', projectId], queryFn: () => api.scans(projectId), enabled: Boolean(projectId) })
  const scans = scansQuery.data?.items ?? []
  const selectedScanId = scans.some(scan => scan.id === scanId) ? scanId : (scans.find(scan => ['completed', 'partial'].includes(scan.status))?.id ?? scans[0]?.id ?? '')
  const userQuery = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false })
  const user = userQuery.data?.user
  const canManage = Boolean(project && user && (project.owner_id === user.id || user.role === 'administrator'))

  if (projectsQuery.isLoading) return <section className="panel"><Loading label="Loading projects…" /></section>
  if (projectsQuery.error) return <section className="panel"><ErrorMessage>{projectsQuery.error.message}</ErrorMessage></section>

  const tabs: { id: Tab; label: string }[] = [
    { id: 'sbom', label: 'SBOM management' }, { id: 'policy', label: 'Security policies' },
    { id: 'remediation', label: 'Remediation' }, { id: 'licenses', label: 'License compliance' },
    { id: 'monitoring', label: 'Monitoring' }, { id: 'alerts', label: 'Alerts' },
  ]

  return <div className="security-center">
    <div className="page-title"><div><span className="eyebrow">PROJECT SECURITY</span><h1>Security center</h1><p>SBOM evidence, policy gates, remediation, licenses and continuous monitoring.</p></div><ShieldCheck size={22} /></div>
    {projects.length === 0 ? <section className="panel empty-state"><FileBox size={25} /><h2>Create a project to get started</h2><p>Security center features operate on a project inventory and scan history.</p><Link to="/app/projects" className="button button-primary">Open projects</Link></section> : <>
      <section className="panel security-scope">
        <label>Project<select aria-label="Security center project" value={projectId} onChange={event => setRequestedProjectId(event.target.value)}>{projects.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        {tab !== 'sbom' && tab !== 'alerts' && <label>Scan<select aria-label="Security center scan" value={selectedScanId} onChange={event => setScanId(event.target.value)}><option value="">Choose a scan</option>{scans.map(scan => <option key={scan.id} value={scan.id}>{scan.source_filename} · {scan.status} · {new Date(scan.created_at).toLocaleDateString()}</option>)}</select></label>}
        {!canManage && project && <span className="pill pill-neutral">Read only</span>}
      </section>
      <div className="security-tabs" role="tablist" aria-label="Security center features">{tabs.map(item => <button key={item.id} className={tab === item.id ? 'active' : ''} role="tab" aria-selected={tab === item.id} onClick={() => setTab(item.id)}>{item.label}</button>)}</div>
      {!projectId ? <section className="panel"><Loading label="Choose a project to continue." /></section> : <>
        {tab === 'sbom' && <SBOMSection project={project} canManage={canManage} />}
        {tab === 'policy' && <PolicySection projectId={projectId} scanId={selectedScanId} canManage={canManage} />}
        {tab === 'remediation' && <RemediationSection scanId={selectedScanId} />}
        {tab === 'licenses' && <LicenseSection projectId={projectId} canManage={canManage} />}
        {tab === 'monitoring' && <MonitoringSection projectId={projectId} canManage={canManage} />}
        {tab === 'alerts' && <AlertsSection />}
      </>}
    </>}
  </div>
}

function SBOMSection({ project, canManage }: { project?: Project; canManage: boolean }) {
  const projectId = project?.id ?? ''
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['sboms', projectId], queryFn: () => api.sboms(projectId), enabled: Boolean(projectId) })
  const [file, setFile] = useState<File | null>(null)
  const [left, setLeft] = useState<SourceValue | ''>('')
  const [right, setRight] = useState<SourceValue | ''>('')
  const [diff, setDiff] = useState<SBOMDiff | null>(null)
  const [selectedImport, setSelectedImport] = useState('')
  const [matches, setMatches] = useState<Awaited<ReturnType<typeof api.sbomVulnerabilities>> | null>(null)
  const upload = useMutation({ mutationFn: () => file && projectId ? api.importSbom(projectId, file) : Promise.reject(new Error('Choose a CycloneDX JSON file first')), onSuccess: async () => { setFile(null); await qc.invalidateQueries({ queryKey: ['sboms', projectId] }) } })
  const compare = useMutation({ mutationFn: () => {
    const parse = (source: SourceValue) => { const [kind, id] = source.split(':') as ['imported' | 'generated', string]; return { kind, id } }
    if (!left || !right || left === right) return Promise.reject(new Error('Choose two different SBOM snapshots to compare'))
    return api.compareSboms(projectId, parse(left), parse(right))
  }, onSuccess: setDiff })
  const vulnerabilityCheck = useMutation({ mutationFn: () => selectedImport ? api.sbomVulnerabilities(projectId, selectedImport) : Promise.reject(new Error('Choose an imported SBOM')), onSuccess: setMatches })
  const sources: { value: SourceValue; label: string }[] = [
    ...(query.data?.imported ?? []).map(item => ({ value: `imported:${item.id}` as SourceValue, label: `Imported · ${item.filename}` })),
    ...(query.data?.generated ?? []).map(item => ({ value: `generated:${item.id}` as SourceValue, label: `Generated · ${item.filename} (${item.status})` })),
  ]
  return <div className="security-grid">
    <section className="panel security-panel"><div className="panel-heading"><div><h2>Import CycloneDX SBOM</h2><p>JSON versions 1.4–1.6, max 5 MiB. Package versions remain BOM declarations.</p></div><FileBox size={19} /></div>
      {upload.error && <ErrorMessage>{upload.error.message}</ErrorMessage>}{upload.isSuccess && <Notice>SBOM validated and saved to this project.</Notice>}
      <form className="security-inline-form" onSubmit={(event: FormEvent) => { event.preventDefault(); upload.mutate() }}><label className="security-file-label">CycloneDX JSON<input type="file" accept="application/json,.json" onChange={event => setFile(event.target.files?.[0] ?? null)} disabled={!canManage} /></label><button className="button button-primary" disabled={!canManage || !file || upload.isPending}>{upload.isPending ? 'Validating…' : 'Import SBOM'}</button></form>
      {query.isLoading ? <Loading label="Loading SBOM snapshots…" /> : query.error ? <ErrorMessage>{query.error.message}</ErrorMessage> : <div className="security-list">{sources.length ? sources.map(item => <div className="security-list-row" key={item.value}><FileText size={16} /><span>{item.label}</span><small>{[...(query.data?.imported ?? []), ...(query.data?.generated ?? [])].find(row => row.id === item.value.split(':')[1])?.component_count ?? 0} components</small></div>) : <p className="security-muted">No imported or generated SBOMs yet. Complete a scan or import a CycloneDX file.</p>}</div>}
    </section>
    <section className="panel security-panel"><div className="panel-heading"><div><h2>Compare SBOM snapshots</h2><p>Changes are identified by package identity and version.</p></div></div>
      <div className="security-comparison-selects"><label>From<select value={left} onChange={event => setLeft(event.target.value as SourceValue)}><option value="">Choose a BOM</option>{sources.map(source => <option value={source.value} key={source.value}>{source.label}</option>)}</select></label><label>To<select value={right} onChange={event => setRight(event.target.value as SourceValue)}><option value="">Choose a BOM</option>{sources.map(source => <option value={source.value} key={source.value}>{source.label}</option>)}</select></label></div>
      {compare.error && <ErrorMessage>{compare.error.message}</ErrorMessage>}<button className="button button-primary" disabled={!left || !right || compare.isPending} onClick={() => compare.mutate()}>{compare.isPending ? 'Comparing…' : 'Compare snapshots'}</button>
      {diff && <div className="security-results"><div className="security-counts"><span><strong>{diff.counts.added}</strong> added</span><span><strong>{diff.counts.removed}</strong> removed</span><span><strong>{diff.counts.changed}</strong> changed</span></div><button className="button button-outline button-small" onClick={() => downloadJSON(`depshield-sbom-diff-${diff.left.id}-${diff.right.id}.json`, diff)}><Download size={15} /> Download comparison JSON</button><JsonRows title="Added components" rows={diff.added} /><JsonRows title="Removed components" rows={diff.removed} /><JsonRows title="Changed components" rows={diff.changed} />{diff.notes.map(note => <p className="security-muted" key={note}>{note}</p>)}</div>}
    </section>
    <section className="panel security-panel"><div className="panel-heading"><div><h2>Check imported components</h2><p>Exact package URL and version queries use OSV where supported.</p></div><RefreshCw size={18} /></div>
      <label>Imported SBOM<select value={selectedImport} onChange={event => setSelectedImport(event.target.value)}><option value="">Choose an imported BOM</option>{(query.data?.imported ?? []).map(item => <option value={item.id} key={item.id}>{item.filename}</option>)}</select></label>
      {vulnerabilityCheck.error && <ErrorMessage>{vulnerabilityCheck.error.message}</ErrorMessage>}<button className="button button-outline" disabled={!selectedImport || vulnerabilityCheck.isPending} onClick={() => vulnerabilityCheck.mutate()}>{vulnerabilityCheck.isPending ? 'Querying OSV…' : 'Check vulnerabilities'}</button>
      {matches && <><p className="security-muted">Source status: <strong>{matches.status}</strong>. {matches.note}</p>{matches.items.length ? <div className="security-list">{matches.items.map((item, index) => <div className="security-list-row" key={`${item.osv_id}-${index}`}><AlertTriangle size={15} /><span><strong>{item.osv_id}</strong> · {String(item.component.name ?? '')} {String(item.component.version ?? '')}<small>{item.summary || 'No advisory summary provided'}</small></span></div>)}</div> : <p className="security-muted">No advisories were returned for the queried components. Check the source status before treating this as clear.</p>}</>}
    </section>
  </div>
}

function JsonRows({ title, rows }: { title: string; rows: Record<string, unknown>[] }) {
  if (!rows.length) return null
  return <details className="security-details"><summary>{title} ({rows.length})</summary><pre>{JSON.stringify(rows, null, 2)}</pre></details>
}

function PolicySection({ projectId, scanId, canManage }: { projectId: string; scanId: string; canManage: boolean }) {
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['security-policy', projectId], queryFn: () => api.securityPolicy(projectId) })
  const [edited, setEdited] = useState<SecurityPolicy | null>(null)
  const form = edited ?? query.data ?? null
  const [result, setResult] = useState<PolicyEvaluation | null>(null)
  const save = useMutation({ mutationFn: () => form ? api.updateSecurityPolicy(projectId, {
    max_allowed_priority: form.max_allowed_priority, fail_on_kev: form.fail_on_kev,
    partial_behavior: form.partial_behavior, unavailable_behavior: form.unavailable_behavior,
    fail_on_unknown_license: form.fail_on_unknown_license,
    allowed_licenses: form.allowed_licenses, restricted_licenses: form.restricted_licenses,
  }) : Promise.reject(new Error('Policy is not loaded')), onSuccess: async data => { setEdited(data); await qc.invalidateQueries({ queryKey: ['security-policy', projectId] }) } })
  const evaluate = useMutation({ mutationFn: () => api.evaluatePolicy(scanId), onSuccess: setResult })
  const update = (value: Partial<SecurityPolicy>) => { if (form) setEdited({ ...form, ...value }) }
  if (query.isLoading) return <section className="panel"><Loading label="Loading project policy…" /></section>
  if (query.error || !form) return <section className="panel"><ErrorMessage>{query.error?.message || 'Policy could not be loaded'}</ErrorMessage></section>
  return <div className="security-grid">
    <section className="panel security-panel"><div className="panel-heading"><div><h2>Project security policy</h2><p>Controls are stored with the project and can be evaluated as a CI gate.</p></div><ShieldCheck size={19} /></div>
      <div className="form-stack"><label>Maximum allowed vulnerability priority<select value={form.max_allowed_priority} onChange={event => update({ max_allowed_priority: event.target.value as SecurityPolicy['max_allowed_priority'] })}><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select><small>Findings above this level fail the gate.</small></label>
        <label className="check-label"><input type="checkbox" checked={form.fail_on_kev} onChange={event => update({ fail_on_kev: event.target.checked })} /> Fail for known exploited vulnerabilities</label>
        <label>Partial scan behavior<select value={form.partial_behavior} onChange={event => update({ partial_behavior: event.target.value as SecurityPolicy['partial_behavior'] })}><option value="warning">Warning</option><option value="fail">Fail</option></select></label>
        <label>Unavailable intelligence behavior<select value={form.unavailable_behavior} onChange={event => update({ unavailable_behavior: event.target.value as SecurityPolicy['unavailable_behavior'] })}><option value="warning">Warning</option><option value="fail">Fail</option></select></label>
        <label>Allowed licenses (SPDX identifiers, comma separated)<input value={form.allowed_licenses.join(', ')} onChange={event => update({ allowed_licenses: parseList(event.target.value) })} placeholder="MIT, Apache-2.0" /></label>
        <label>Restricted licenses<input value={form.restricted_licenses.join(', ')} onChange={event => update({ restricted_licenses: parseList(event.target.value) })} placeholder="GPL-3.0-only" /></label>
        <label className="check-label"><input type="checkbox" checked={form.fail_on_unknown_license} onChange={event => update({ fail_on_unknown_license: event.target.checked })} /> Fail when license evidence is unknown</label>
        {save.error && <ErrorMessage>{save.error.message}</ErrorMessage>}{save.isSuccess && <Notice>Policy saved.</Notice>}
        <button className="button button-primary" disabled={!canManage || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save project policy'}</button>
      </div>
    </section>
    <section className="panel security-panel"><div className="panel-heading"><div><h2>Evaluate selected scan</h2><p>Partial scans and unavailable sources cannot produce a silent pass.</p></div></div>
      <button className="button button-primary" disabled={!scanId || evaluate.isPending} onClick={() => evaluate.mutate()}>{evaluate.isPending ? 'Evaluating…' : 'Evaluate policy'}</button>
      {evaluate.error && <ErrorMessage>{evaluate.error.message}</ErrorMessage>}{result && <div className="security-results"><span className={`policy-result status-${result.status.toLowerCase()}`}>{result.status}</span>{result.failures.map(item => <p className="security-failure" key={item}>{item}</p>)}{result.warnings.map(item => <p className="security-warning" key={item}>{item}</p>)}<button className="button button-outline button-small" onClick={() => downloadJSON(`depshield-policy-${result.scan_id}.json`, result)}><Download size={15} /> Download policy JSON</button></div>}
    </section>
  </div>
}

function parseList(value: string) { return [...new Set(value.split(',').map(item => item.trim()).filter(Boolean))].slice(0, 100) }

function RemediationSection({ scanId }: { scanId: string }) {
  const [useAI, setUseAI] = useState(false)
  const query = useQuery({ queryKey: ['remediation', scanId, useAI], queryFn: () => api.remediation(scanId, useAI), enabled: Boolean(scanId) })
  if (!scanId) return <section className="panel"><p className="security-muted">Choose a scan to build a remediation plan.</p></section>
  const groups = query.data?.groups
  const count = groups ? Object.values(groups).reduce((sum, items) => sum + items.length, 0) : 0
  return <div className="security-grid"><section className="panel security-panel security-panel-wide"><div className="panel-heading"><div><h2>Evidence-based remediation planner</h2><p>Targets come from stored OSV fixed-version evidence. DepShield does not edit files or install packages.</p></div><FileText size={19} /></div>
    <label className="check-label"><input type="checkbox" checked={useAI} onChange={event => setUseAI(event.target.checked)} /> Request an optional Ollama explanation; use a labelled deterministic fallback when unavailable</label>
    {query.isLoading ? <Loading label="Building plan from scan evidence…" /> : query.error ? <ErrorMessage>{query.error.message}</ErrorMessage> : groups && count === 0 ? <p className="security-muted">This scan has no stored vulnerability findings.</p> : null}
    {groups && <><a className="button button-outline button-small" href={`/api/v1/scans/${scanId}/remediation.pdf`}><Download size={15} /> Download PDF plan</a><div className="security-remediation-groups">{Object.entries({ urgent: 'Urgent', high: 'High priority', routine: 'Routine', needs_evidence: 'Needs more evidence' }).map(([key, title]) => <section key={key}><h3>{title} <span>{groups[key as keyof typeof groups].length}</span></h3>{groups[key as keyof typeof groups].length ? groups[key as keyof typeof groups].map((item, index) => <article className="security-remediation-item" key={`${item.vulnerability_id}-${index}`}><div><strong>{item.package} {item.current_version || '(version unknown)'}</strong><span>{item.vulnerability_id} · {item.official_severity} · {item.priority}{item.known_exploited ? ' · Known exploited' : ''}</span></div><p>{item.summary || 'No advisory summary provided'}</p>{item.affected_ranges.length > 0 && <details><summary>Affected range evidence</summary><pre>{JSON.stringify(item.affected_ranges, null, 2)}</pre></details>}<p>{item.reason}{item.recommended_target ? ` Target: ${item.recommended_target}` : ''}</p>{item.ai_explanation && <p className="security-ai-note"><strong>{item.ai_explanation.generated_by === 'ollama' ? 'Ollama generated' : 'Deterministic fallback'}:</strong> {item.ai_explanation.text}</p>}</article>) : <p className="security-muted">No items in this group.</p>}</section>)}</div>{groups && query.data?.limitations.map(note => <p className="security-muted" key={note}>{note}</p>)}</>}
  </section></div>
}

function LicenseSection({ projectId, canManage }: { projectId: string; canManage: boolean }) {
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['licenses', projectId], queryFn: () => api.licenseInventory(projectId) })
  const refresh = useMutation({ mutationFn: () => api.refreshLicenses(projectId), onSuccess: async () => { await qc.invalidateQueries({ queryKey: ['licenses', projectId] }) } })
  if (query.isLoading) return <section className="panel"><Loading label="Loading license evidence…" /></section>
  if (query.error) return <section className="panel"><ErrorMessage>{query.error.message}</ErrorMessage></section>
  const inventory = query.data as LicenseInventory
  return <div className="security-grid"><section className="panel security-panel security-panel-wide"><div className="panel-heading"><div><h2>License inventory</h2><p>Registry evidence is verified against package metadata; manifest declarations remain marked unverified.</p></div><FileText size={19} /></div>
    <div className="security-actions"><button className="button button-outline" disabled={!canManage || refresh.isPending} onClick={() => refresh.mutate()}><RefreshCw size={15} /> {refresh.isPending ? 'Checking registries…' : 'Refresh package metadata'}</button><a className="button button-outline button-small" href={`/api/v1/projects/${projectId}/licenses/report.json`}><Download size={15} /> JSON</a><a className="button button-outline button-small" href={`/api/v1/projects/${projectId}/licenses/report.pdf`}><Download size={15} /> PDF</a></div>
    {refresh.error && <ErrorMessage>{refresh.error.message}</ErrorMessage>}{refresh.isSuccess && <Notice>Registry lookup finished for {refresh.data.checked} package entries. Review evidence status below.</Notice>}
    <p className={`policy-result status-${inventory.evaluation.status === 'clear' ? 'pass' : 'warning'}`}>{inventory.evaluation.status.replace('_', ' ').toUpperCase()}</p><p className="security-muted">{inventory.evaluation.disclaimer}</p>
    <div className="security-table-wrap"><table className="security-table"><thead><tr><th>Package</th><th>Version</th><th>License</th><th>Evidence</th></tr></thead><tbody>{inventory.items.map(item => <tr key={item.component_id}><td>{item.name}<small>{item.ecosystem}</small></td><td>{item.version || 'Unverified'}</td><td>{item.license || 'UNKNOWN'}{!item.verified_metadata && item.license && <small>Declared, unverified</small>}</td><td>{item.verified_metadata ? 'Registry metadata' : item.evidence_status}</td></tr>)}</tbody></table></div>
  </section></div>
}

function MonitoringSection({ projectId, canManage }: { projectId: string; canManage: boolean }) {
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['monitoring-schedule', projectId], queryFn: () => api.monitoringSchedule(projectId) })
  const [edited, setEdited] = useState<{ hours: number; active: boolean } | null>(null)
  const hours = edited?.hours ?? query.data?.interval_hours ?? 24
  const active = edited?.active ?? (query.data?.configured ? query.data.active : true)
  const save = useMutation({ mutationFn: () => api.saveMonitoringSchedule(projectId, hours, active), onSuccess: async () => { setEdited(null); await qc.invalidateQueries({ queryKey: ['monitoring-schedule', projectId] }) } })
  const remove = useMutation({ mutationFn: () => api.deleteMonitoringSchedule(projectId), onSuccess: async () => { setEdited(null); await qc.invalidateQueries({ queryKey: ['monitoring-schedule', projectId] }) } })
  if (query.isLoading) return <section className="panel"><Loading label="Loading monitoring schedule…" /></section>
  if (query.error) return <section className="panel"><ErrorMessage>{query.error.message}</ErrorMessage></section>
  const schedule = query.data as MonitoringSchedule
  return <div className="security-grid"><section className="panel security-panel"><div className="panel-heading"><div><h2>Continuous monitoring</h2><p>The worker queues a new scan from the latest saved dependency inventory on each due interval.</p></div><TimerReset size={19} /></div>
    {schedule.configured ? <p className="security-muted">{schedule.active ? 'Active' : 'Paused'} · every {schedule.interval_hours} hours · next due {schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : 'not scheduled'}</p> : <p className="security-muted">No persistent schedule is configured for this project.</p>}
    <label>Rescan interval in hours<input type="number" min={6} max={720} value={hours} onChange={event => setEdited({ hours: Number(event.target.value), active })} disabled={!canManage} /></label>
    <label className="check-label"><input type="checkbox" checked={active} onChange={event => setEdited({ hours, active: event.target.checked })} disabled={!canManage} /> Schedule is active</label>
    {save.error && <ErrorMessage>{save.error.message}</ErrorMessage>}{save.isSuccess && <Notice>Monitoring schedule saved.</Notice>}{remove.error && <ErrorMessage>{remove.error.message}</ErrorMessage>}
    <div className="security-actions"><button className="button button-primary" disabled={!canManage || hours < 6 || hours > 720 || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : schedule.configured ? 'Save or pause schedule' : 'Create schedule'}</button>{schedule.configured && <button className="button button-outline" disabled={!canManage || remove.isPending} onClick={() => remove.mutate()}>{remove.isPending ? 'Removing…' : 'Delete schedule'}</button>}</div>
    <p className="security-muted">New findings and newly known exploited findings create in-app alerts. “No longer detected” alerts are only created when both comparison scans are complete.</p>
  </section></div>
}

function AlertsSection() {
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['notifications'], queryFn: () => api.notifications(false) })
  const prefsQuery = useQuery({ queryKey: ['notification-preferences'], queryFn: api.notificationPreferences })
  const mark = useMutation({ mutationFn: api.markNotificationRead, onSuccess: async () => { await qc.invalidateQueries({ queryKey: ['notifications'] }) } })
  const markAll = useMutation({ mutationFn: api.markAllNotificationsRead, onSuccess: async () => { await qc.invalidateQueries({ queryKey: ['notifications'] }) } })
  const prefs = useMutation({ mutationFn: api.saveNotificationPreferences, onSuccess: async () => { await qc.invalidateQueries({ queryKey: ['notification-preferences'] }) } })
  if (query.isLoading || prefsQuery.isLoading) return <section className="panel"><Loading label="Loading notifications…" /></section>
  if (query.error || prefsQuery.error) return <section className="panel"><ErrorMessage>{query.error?.message || prefsQuery.error?.message || 'Could not load notifications'}</ErrorMessage></section>
  return <div className="security-grid"><section className="panel security-panel security-panel-wide"><div className="panel-heading"><div><h2>Security notifications</h2><p>Alerts are generated from persisted scan comparisons, with uncertainty preserved.</p></div><Bell size={19} /></div>
    <div className="security-actions"><button className="button button-outline button-small" disabled={!query.data?.items.some(item => !item.read_at) || markAll.isPending} onClick={() => markAll.mutate()}><Check size={15} /> Mark all read</button><label className="check-label"><input type="checkbox" checked={prefsQuery.data?.email_enabled ?? false} disabled={!prefsQuery.data?.smtp_configured || prefs.isPending} onChange={event => prefs.mutate(event.target.checked)} /> Email alerts {prefsQuery.data?.smtp_configured ? '' : '(SMTP not configured)'}</label></div>
    {prefs.error && <ErrorMessage>{prefs.error.message}</ErrorMessage>}{prefs.isSuccess && <Notice>Notification preferences saved.</Notice>}
    {query.data?.items.length ? <div className="security-list">{query.data.items.map(item => <article className={`notification-card ${item.read_at ? 'is-read' : ''}`} key={item.id}><div><strong>{item.title}</strong><p>{item.message}</p><small>{new Date(item.created_at).toLocaleString()} · email {item.email_status}</small></div>{!item.read_at && <button className="button button-outline button-small" disabled={mark.isPending} onClick={() => mark.mutate(item.id)}>Mark read</button>}</article>)}</div> : <p className="security-muted">No security alerts yet. Monitoring alerts appear after completed scans detect a change.</p>}
  </section></div>
}
