import { describe, expect, it } from 'vitest'
import { formatBytes } from './formatBytes'

describe('formatBytes', () => {
  it('uses readable byte, kilobyte, and megabyte units', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KB')
    expect(formatBytes(10 * 1024 * 1024)).toBe('10.0 MB')
  })
})
