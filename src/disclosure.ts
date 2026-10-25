import { canonicalize } from './canonical.ts'

/**
 * SPEC.md section 10 (sdc-kl-v1). Counted rows are grouped by their quasi-identifiers (every
 * revealed field except choice and carry, with its level). Each group needs at least k rows,
 * at least l distinct choices, and at least minChoiceSupport rows behind each choice it shows.
 * A group holding every row of its row type (and dimension) is the stage total, public anyway,
 * so it is exempt from the l and minChoiceSupport rules.
 */
export type PublishedRow = { rowType: 'main' | 'demographic'; dimension?: string; choice: string; qis: Record<string, { level: string; value: string | boolean }> }

export type DisclosureViolation = { rowType: string; dimension?: string; group: Record<string, { level: string; value: string | boolean }>; rows: number; distinctChoices: number; rule: 'k' | 'l' | 'minChoiceSupport' }

export function checkDisclosure(rows: PublishedRow[], k: number, l: number, minChoiceSupport = 1): DisclosureViolation[] {
  const totals = new Map<string, number>()
  const groups = new Map<string, { sample: PublishedRow; count: number; choices: Map<string, number>; population: string }>()
  for (const r of rows) {
    const population = canonicalize([r.rowType, r.dimension ?? null])
    totals.set(population, (totals.get(population) ?? 0) + 1)
    const key = canonicalize([r.rowType, r.dimension ?? null, r.qis])
    const g = groups.get(key) ?? { sample: r, count: 0, choices: new Map<string, number>(), population }
    g.count++
    g.choices.set(r.choice, (g.choices.get(r.choice) ?? 0) + 1)
    groups.set(key, g)
  }
  const out: DisclosureViolation[] = []
  for (const g of groups.values()) {
    const base = { rowType: g.sample.rowType, ...(g.sample.dimension ? { dimension: g.sample.dimension } : {}), group: g.sample.qis, rows: g.count, distinctChoices: g.choices.size }
    const wholeStage = g.count === totals.get(g.population)
    if (g.count < k) out.push({ ...base, rule: 'k' })
    else if (!wholeStage && g.choices.size < l) out.push({ ...base, rule: 'l' })
    else if (!wholeStage && [...g.choices.values()].some((n) => n < minChoiceSupport)) out.push({ ...base, rule: 'minChoiceSupport' })
  }
  return out
}
