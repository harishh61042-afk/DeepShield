export function scanHasStableEvidence(status: string | null | undefined): boolean {
  return Boolean(status) && status !== 'queued' && status !== 'processing'
}
