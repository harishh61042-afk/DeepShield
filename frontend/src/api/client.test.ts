import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

let request: (path: string, init?: RequestInit) => Promise<unknown>

beforeEach(async () => {
  vi.resetModules()
  request = (await import('./client')).request
})

afterEach(() => { vi.unstubAllGlobals() })

describe('API client security behavior', () => {
  it('loads CSRF and sends it on state-changing requests with credentials', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'test-csrf' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 201 }))
    vi.stubGlobal('fetch', fetchMock)
    await request('/projects', { method: 'POST', body: JSON.stringify({ name: 'project' }) })
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/auth/csrf')
    const init = fetchMock.mock.calls[1][1] as RequestInit
    expect(init.credentials).toBe('include')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('test-csrf')
  })

  it('surfaces the server error without hiding its status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Project not found' }), { status: 404 })))
    await expect(request('/projects/missing')).rejects.toMatchObject({ message: 'Project not found', status: 404 })
  })

  it('formats structured validation errors as readable messages', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: [
      { loc: ['body', 'email'], msg: 'value is not a valid email address', type: 'value_error' },
    ] }), { status: 422 })))
    await expect(request('/auth/register', { method: 'POST', body: '{}' })).rejects.toMatchObject({
      message: 'value is not a valid email address', status: 422,
    })
  })

  it('refreshes the CSRF token after logout before the next login', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'before-logout' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'Signed out' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'after-logout' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ user: {}, csrf_token: 'after-login' }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await request('/auth/logout', { method: 'POST' })
    await request('/auth/login', { method: 'POST', body: JSON.stringify({ email: 'qa@example.com', password: 'test' }) })

    expect(fetchMock.mock.calls.map(call => call[0])).toEqual([
      '/api/v1/auth/csrf', '/api/v1/auth/logout', '/api/v1/auth/csrf', '/api/v1/auth/login',
    ])
    const loginInit = fetchMock.mock.calls[3][1] as RequestInit
    expect(new Headers(loginInit.headers).get('X-CSRF-Token')).toBe('after-logout')
  })

  it('retries a state-changing request once after a stale CSRF token is rejected', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'stale-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'CSRF validation failed' }), { status: 403 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'fresh-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'ok' }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(request('/projects', { method: 'POST', body: JSON.stringify({ name: 'project' }) })).resolves.toEqual({ message: 'ok' })
    expect(fetchMock).toHaveBeenCalledTimes(4)
    const retryInit = fetchMock.mock.calls[3][1] as RequestInit
    expect(new Headers(retryInit.headers).get('X-CSRF-Token')).toBe('fresh-token')
  })
})
