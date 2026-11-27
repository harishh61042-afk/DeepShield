import { describe, expect, it } from 'vitest'
import { scanHasStableEvidence } from './scanReadiness'

describe('scan evidence loading', () => {
  it('does not load evidence until a scan status exists and is terminal', () => {
    expect(scanHasStableEvidence(undefined)).toBe(false)
    expect(scanHasStableEvidence('queued')).toBe(false)
    expect(scanHasStableEvidence('processing')).toBe(false)
    expect(scanHasStableEvidence('completed')).toBe(true)
    expect(scanHasStableEvidence('partial')).toBe(true)
  })
})
