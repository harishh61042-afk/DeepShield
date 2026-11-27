import { randomUUID } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { expect, test } from '@playwright/test'

test('real user can register, scan, use all security-center features, export reports and return', async ({ page }) => {
  const email = `depshield-e2e-${randomUUID()}@example.com`
  const password = 'E2E-security-project-2026!'

  await page.goto('/')
  const cookieNotice = page.getByRole('button', { name: 'Got it' })
  if (await cookieNotice.isVisible()) await cookieNotice.click()
  await page.getByRole('link', { name: 'Create account' }).first().click()
  await page.getByLabel('Display name').fill('Security E2E')
  await page.getByLabel('Email address').fill(email)
  await page.locator('input[type="password"]').fill(password)
  await page.getByLabel(/I agree to the Terms/).check()
  await page.getByLabel(/I confirm I am at least 18 years old/).check()
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByRole('status')).toContainText('If registration is available')
  await page.locator('.auth-switch').getByRole('link', { name: 'Sign in' }).click()
  await page.getByLabel('Email address').fill(email)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/app$/)

  await page.locator('.side-nav').getByRole('link', { name: 'Projects' }).click()
  await page.getByRole('button', { name: 'Create project' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Create a project' })
  await dialog.getByLabel('Project name').fill(`Supply chain ${Date.now()}`)
  await dialog.getByLabel('Primary ecosystem').selectOption('python')
  await dialog.getByRole('button', { name: 'Create project' }).click()
  await expect(page).toHaveURL(/\/app\/projects\/[0-9a-f-]+$/)

  const projectId = page.url().split('/').pop()!
  const upload = page.locator('.upload-top-button input[type="file"]')
  await upload.setInputFiles({ name: 'requirements.txt', mimeType: 'text/plain', buffer: Buffer.from('Django==3.2.0\n') })
  const scanLink = page.getByRole('link', { name: 'requirements.txt' }).first()
  await expect(scanLink).toBeVisible({ timeout: 30_000 })
  await scanLink.click()
  await expect(page.getByText(/Scan completed|Partial scan/)).toBeVisible({ timeout: 360_000 })
  const scanId = page.url().split('/').pop()!

  await page.getByRole('tab', { name: /Components/ }).click()
  await expect(page.getByText('Django', { exact: false }).first()).toBeVisible()
  await page.getByRole('tab', { name: /Findings/ }).click()
  const finding = page.locator('.finding-card').first()
  await expect(finding).toBeVisible({ timeout: 60_000 })
  await finding.getByRole('button', { name: 'Expand finding details' }).click()
  await finding.getByRole('button', { name: 'Explain this finding' }).click()
  await expect(finding.getByText(/Deterministic explanation|Local Ollama explanation/)).toBeVisible({ timeout: 60_000 })

  const reportDownload = page.waitForEvent('download')
  await page.getByRole('link', { name: 'PDF report' }).click()
  expect((await reportDownload).suggestedFilename()).toContain('.pdf')

  await page.locator('.side-nav').getByRole('link', { name: 'Security center' }).click()
  await expect(page.getByRole('heading', { name: 'Security center' })).toBeVisible()
  const palette = await page.evaluate(() => {
    const tokens = getComputedStyle(document.documentElement)
    return {
      background: tokens.getPropertyValue('--bg').trim().toLowerCase(),
      surface: tokens.getPropertyValue('--surface').trim().toLowerCase(),
      cream: tokens.getPropertyValue('--cream').trim().toLowerCase(),
      primary: tokens.getPropertyValue('--primary').trim().toLowerCase(),
      slate: tokens.getPropertyValue('--slate').trim().toLowerCase(),
      softGrey: tokens.getPropertyValue('--soft-gray').trim().toLowerCase(),
      text: tokens.getPropertyValue('--text').trim().toLowerCase(),
      selected: getComputedStyle(document.querySelector('.side-nav a.active')!).backgroundColor,
      primaryButton: getComputedStyle(document.querySelector('.button-primary')!).backgroundColor,
    }
  })
  expect(palette).toMatchObject({
    background: '#f7f6f1', surface: '#ffffff', cream: '#fbf4e5', primary: '#f5d65e',
    slate: '#a7adb8', softGrey: '#ecedef', text: '#202127',
    selected: 'rgb(245, 214, 94)', primaryButton: 'rgb(245, 214, 94)',
  })

  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    components: [{ type: 'library', name: 'Django', version: '3.2.0', purl: 'pkg:pypi/Django@3.2.0', 'bom-ref': 'pkg:pypi/Django@3.2.0' }],
  }
  const importResponse = page.waitForResponse(response => response.url().includes(`/projects/${projectId}/sboms/import`) && response.request().method() === 'POST')
  await page.getByLabel('CycloneDX JSON').setInputFiles({ name: 'release.cdx.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(sbom)) })
  await page.getByRole('button', { name: 'Import SBOM' }).click()
  const imported = await (await importResponse).json() as { id: string }
  await expect(page.getByRole('status').filter({ hasText: 'SBOM validated and saved' })).toBeVisible()

  const comparison = page.locator('.security-comparison-selects')
  await comparison.getByLabel('From').selectOption({ value: `generated:${scanId}` })
  await comparison.getByLabel('To').selectOption({ value: `imported:${imported.id}` })
  await page.getByRole('button', { name: 'Compare snapshots' }).click()
  await expect(page.getByText(/added|removed|changed/).first()).toBeVisible()
  await page.getByLabel('Imported SBOM').selectOption(imported.id)
  await page.getByRole('button', { name: 'Check vulnerabilities' }).click()
  await expect(page.getByText(/Source status:/)).toBeVisible({ timeout: 90_000 })

  await page.getByRole('tab', { name: 'Security policies' }).click()
  await page.getByRole('button', { name: 'Save project policy' }).click()
  await page.getByRole('button', { name: 'Evaluate policy' }).click()
  await expect(page.locator('.policy-result')).toHaveText(/PASS|WARNING|FAIL/)

  await page.getByRole('tab', { name: 'Remediation' }).click()
  await expect(page.getByRole('heading', { name: 'Evidence-based remediation planner' })).toBeVisible()
  const planDownload = page.waitForEvent('download')
  await page.getByRole('link', { name: 'Download PDF plan' }).click()
  expect((await planDownload).suggestedFilename()).toContain('remediation')

  await page.getByRole('tab', { name: 'License compliance' }).click()
  await page.getByRole('button', { name: /Refresh package metadata/ }).click()
  await expect(page.getByText(/Registry lookup finished/)).toBeVisible({ timeout: 90_000 })
  const licenseDownload = page.waitForEvent('download')
  await page.getByRole('link', { name: 'PDF', exact: true }).click()
  expect((await licenseDownload).suggestedFilename()).toContain('licenses')

  await page.getByRole('tab', { name: 'Monitoring' }).click()
  await page.getByRole('button', { name: 'Create schedule' }).click()
  await expect(page.getByText(/Active · every 24 hours/)).toBeVisible()
  await page.getByLabel('Schedule is active').uncheck()
  await page.getByRole('button', { name: 'Save or pause schedule' }).click()
  await expect(page.getByText(/Paused · every 24 hours/)).toBeVisible()
  await page.getByLabel('Schedule is active').check()
  await page.getByRole('button', { name: 'Save or pause schedule' }).click()
  await expect(page.getByText(/Active · every 24 hours/)).toBeVisible()
  await page.getByRole('button', { name: 'Delete schedule' }).click()
  await expect(page.getByText('No persistent schedule is configured for this project.')).toBeVisible()

  await page.getByRole('tab', { name: 'Alerts' }).click()
  await expect(page.getByText('Security notifications')).toBeVisible()
  const markAll = page.getByRole('button', { name: 'Mark all read' })
  if (await markAll.isEnabled()) await markAll.click()

  for (const width of [1280, 768, 390]) {
    await page.setViewportSize({ width, height: 850 })
    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
    expect(scrollWidth).toBeLessThanOrEqual(width)
  }
  await page.getByRole('button', { name: 'Open menu' }).click()
  await expect(page.getByRole('navigation', { name: 'Workspace navigation' }).getByRole('link', { name: 'Security center' })).toBeVisible()

  for (const route of ['/app', '/app/projects', `/app/projects/${projectId}`, `/app/scans/${scanId}`, '/app/vulnerabilities', '/app/settings']) {
    await page.goto(route)
    await expect(page.locator('main h1').first()).toBeVisible()
  }

  await page.setViewportSize({ width: 1280, height: 850 })
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL('/login')
  for (const route of ['/', '/about', '/how-it-works', '/faq', '/privacy', '/terms', '/cookies', '/free-use', '/register', '/forgot-password', '/reset-password']) {
    await page.goto(route)
    await expect(page.locator('h1, h2').first()).toBeVisible()
  }
  await page.goto('/login')
  await page.getByLabel('Email address').fill(email)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/app$/)
})
