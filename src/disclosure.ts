import { canonicalize } from './canonical.ts'

/**
 * SPEC.md section 10 (sdc-kl-v1): published rows grouped by their revealed
 * quasi-identifiers (every revealed field except choice, with its level) must each have
 * at least k rows and at least l distinct choices.
 */
export type PublishedRow = { rowType: 'main' | 'demographic'; dimension?: string; choice: string; qis: Record<string, { level: string; value: string | boolean }> }

export type DisclosureViolation = { rowType: string; dimension?: string; group: Record<string, { level: string; value: string | boolean }>; rows: number; distinctChoices: number; rule: 'k' | 'l' }

export function checkDisclosure(rows: PublishedRow[], k: number, l: number): DisclosureViolation[] {
  const groups = new Map<string, { sample: PublishedRow; count: number; choices: Set<string> }>()
  for (const r of rows) {
    const key = canonicalize([r.rowType, r.dimension ?? null, r.qis])
    const g = groups.get(key) ?? { sample: r, count: 0, choices: new Set<string>() }
    g.count++
    g.choices.add(r.choice)
    groups.set(key, g)
  }
  const out: DisclosureViolation[] = []
  for (const g of groups.values()) {
    const base = { rowType: g.sample.rowType, ...(g.sample.dimension ? { dimension: g.sample.dimension } : {}), group: g.sample.qis, rows: g.count, distinctChoices: g.choices.size }
    if (g.count < k) out.push({ ...base, rule: 'k' })
    else if (g.choices.size < l) out.push({ ...base, rule: 'l' })
  }
  return out
}
