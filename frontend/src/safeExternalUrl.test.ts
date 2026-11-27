import { describe, expect, it } from 'vitest'
import { safeExternalUrl } from './safeExternalUrl'

describe('safeExternalUrl', () => {
  it('allows ordinary HTTP and HTTPS advisory references', () => {
    expect(safeExternalUrl('https://osv.dev/vulnerability/EXAMPLE')).toBe('https://osv.dev/vulnerability/EXAMPLE')
    expect(safeExternalUrl('http://example.com/advisory')).toBe('http://example.com/advisory')
  })

  it.each(['javascript:alert(1)', 'data:text/html,hello', '//example.com/path', 'https://user:pass@example.com/'])('rejects unsafe or ambiguous references: %s', value => {
    expect(safeExternalUrl(value)).toBeNull()
  })
})
