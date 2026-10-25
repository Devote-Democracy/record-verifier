import { canonicalize } from './canonical.ts'
import { ballotMessage, opensCommitment, type RevealedField } from './commitment.ts'
import { checkDisclosure, type DisclosureViolation, type PublishedRow } from './disclosure.ts'
import type { Envelope } from './envelope.ts'

/**
 * Recounts one stage from the log (SPEC.md sections 6, 8, 9, 10) and compares the result
 * with the stage's `tally` entry. Membership proofs are checked by an optional
 * `verifyProof` callback (Semaphore v4 needs a Groth16 verifier and its keys).
 */
export type LoggedEntry = { index: number; envelope: Envelope }

export type Issue = { severity: 'error' | 'warning'; entry?: number; message: string }

export type CountTable = { rowType: 'main' | 'demographic'; dimension?: string; field: string; level: string; rows: { value: string | boolean; counts: Record<string, number> }[] }

export type StageRecount = {
  manifest: number
  totals: Record<string, number>
  tables: CountTable[]
  countedRows: number
  carriedRows: number
  undecryptable: number
  disclosureViolations: DisclosureViolation[]
  tallyMatches: boolean | null
  issues: Issue[]
}

type CountedRow = { ballot: number; rowType: 'main' | 'demographic'; dimension?: string; key: string; fields: Record<string, RevealedField>; choice: string; carry: boolean; manifest: number }

/** Voting preferences, not identifying attributes (SPEC.md section 10). */
const NOT_QI = new Set(['choice', 'carry'])

export async function recountStage(entries: LoggedEntry[], manifestIndex: number, opts: { verifyProof?: (ballot: Record<string, any>) => Promise<boolean> } = {}): Promise<StageRecount> {
  const issues: Issue[] = []
  const byIndex = new Map(entries.map((e) => [e.index, e.envelope]))
  const manifest = byIndex.get(manifestIndex)
  if (!manifest || manifest.type !== 'manifest') throw new Error(`entry ${manifestIndex} is not a manifest`)
  if (!opts.verifyProof) issues.push({ severity: 'warning', message: 'Membership proofs were not checked (no Semaphore verifier supplied).' })

  const stats = { undecryptable: 0 }
  const own = await revealedFinals(entries, manifestIndex, manifest, issues, opts.verifyProof, stats)

  // Carry: the latest revealed row per (scope, nullifier) among earlier stages named in carryFrom.
  const carried: CountedRow[] = []
  const carryFrom = new Set<string>(manifest.body.carryFrom ?? [])
  if (carryFrom.size) {
    const earlier = entries.filter((e) => e.envelope.type === 'manifest' && e.index < manifestIndex && carryFrom.has(e.envelope.body.stageId) && e.envelope.body.billKey === manifest.body.billKey)
    const latest = new Map<string, CountedRow>()
    for (const m of earlier.sort((a, b) => a.index - b.index)) {
      const rows = await revealedFinals(entries, m.index, m.envelope, [], opts.verifyProof, { undecryptable: 0 })
      for (const r of rows) latest.set(r.key, r)
    }
    const ownKeys = new Set(own.map((r) => r.key))
    for (const [key, r] of latest) if (r.carry && !ownKeys.has(key)) carried.push(r)
  }

  // Re-reveals: this stage may publish carried rows again at a coarser level (SPEC.md section 6).
  const rereveals = new Map<number, Record<string, RevealedField>>()
  for (const e of entries) {
    if (e.envelope.type !== 'reveal' || e.envelope.body.manifest !== manifestIndex) continue
    for (const row of e.envelope.body.rows) {
      const target = byIndex.get(row.ballot)
      if (target?.type === 'ballot' && target.body.manifest !== manifestIndex && row.fields) rereveals.set(row.ballot, row.fields)
    }
  }
  const carriedByBallot = new Map(carried.map((r, i) => [r.ballot, i]))
  const ladders = manifest.body.disclosure.ladders as Record<string, string[]>
  for (const [ballotIndex, fields] of rereveals) {
    const at = carriedByBallot.get(ballotIndex)
    if (at === undefined) { issues.push({ severity: 'error', entry: ballotIndex, message: 'Re-revealed a ballot that is not carried into this stage.' }); continue }
    const row = carried[at]!
    const commitments = byIndex.get(ballotIndex)!.body.commitments
    let ok = true
    for (const [field, f] of Object.entries(fields)) {
      if (!(await opensCommitment(commitments, field, f))) { ok = false; issues.push({ severity: 'error', entry: ballotIndex, message: `Re-revealed ${field} does not open its commitment.` }); continue }
      const before = row.fields[field]
      if ((field === 'choice' || field === 'carry') && !('withheld' in f) && before && !('withheld' in before) && f.value !== before.value) { ok = false; issues.push({ severity: 'error', entry: ballotIndex, message: `A re-reveal changed ${field}.` }) }
      const ladder = ladders[field === 'value' ? (row.dimension ?? '') : field]
      if (ladder && before && !('withheld' in before) && !('withheld' in f) && ladder.indexOf(f.level) < ladder.indexOf(before.level)) { ok = false; issues.push({ severity: 'error', entry: ballotIndex, message: `A re-reveal made ${field} finer, not coarser.` }) }
    }
    if (ok) carried[at] = { ...row, fields: { ...row.fields, ...fields } }
  }

  const counted = [...own, ...carried]
  const totals: Record<string, number> = Object.fromEntries((manifest.body.choices as string[]).map((c) => [c, 0]))
  const tableMap = new Map<string, CountTable>()
  for (const r of counted) {
    if (r.rowType === 'main') totals[r.choice] = (totals[r.choice] ?? 0) + 1
    for (const [field, f] of Object.entries(r.fields)) {
      if (NOT_QI.has(field) || field === 'carry' || 'withheld' in f) continue
      const tkey = canonicalize([r.rowType, r.dimension ?? null, field, f.level])
      const table = tableMap.get(tkey) ?? { rowType: r.rowType, ...(r.dimension ? { dimension: r.dimension } : {}), field, level: f.level, rows: [] }
      let row = table.rows.find((x) => x.value === f.value)
      if (!row) { row = { value: f.value, counts: {} }; table.rows.push(row) }
      row.counts[r.choice] = (row.counts[r.choice] ?? 0) + 1
      tableMap.set(tkey, table)
    }
  }
  const tables = [...tableMap.values()]

  const published: PublishedRow[] = counted.map((r) => ({
    rowType: r.rowType,
    ...(r.dimension ? { dimension: r.dimension } : {}),
    choice: r.choice,
    qis: Object.fromEntries(Object.entries(r.fields).filter(([k, f]) => !NOT_QI.has(k) && !('withheld' in f)).map(([k, f]) => [k, { level: (f as { level: string }).level, value: (f as { value: string | boolean }).value }])),
  }))
  const { k, l, minChoiceSupport } = manifest.body.disclosure
  const disclosureViolations = checkDisclosure(published, k, l, minChoiceSupport ?? 1)
  for (const v of disclosureViolations) issues.push({ severity: 'error', message: `Published group breaks the ${v.rule} rule (${v.rows} rows, ${v.distinctChoices} choices): ${canonicalize(v.group)}` })

  const tallies = entries.filter((e) => e.envelope.type === 'tally' && e.envelope.body.manifest === manifestIndex)
  let tallyMatches: boolean | null = null
  if (tallies.length > 1) issues.push({ severity: 'error', message: `Stage has ${tallies.length} tally entries` })
  if (tallies.length) {
    const t = tallies.at(-1)!.envelope.body
    tallyMatches = canonicalize(t.totals) === canonicalize(totals) && sameTables(t.tables, tables)
    if (!tallyMatches) issues.push({ severity: 'error', entry: tallies.at(-1)!.index, message: 'The published tally does not match the recount.' })
  }

  if (stats.undecryptable) issues.push({ severity: 'warning', message: `${stats.undecryptable} counted ballot(s) were marked undecryptable and count nowhere.` })
  return { manifest: manifestIndex, totals, tables, countedRows: counted.length, carriedRows: carried.length, undecryptable: stats.undecryptable, disclosureViolations, tallyMatches, issues }
}

async function revealedFinals(entries: LoggedEntry[], manifestIndex: number, manifest: Envelope, issues: Issue[], verifyProof: ((b: Record<string, any>) => Promise<boolean>) | undefined, stats: { undecryptable: number }): Promise<CountedRow[]> {
  const m = manifest.body
  const reveals = entries.filter((e) => e.envelope.type === 'reveal' && e.envelope.body.manifest === manifestIndex)
  const firstReveal = reveals.length ? Math.min(...reveals.map((r) => r.index)) : Infinity

  // Valid ballots, and the final one per (scope, nullifier).
  const finals = new Map<string, LoggedEntry>()
  for (const e of entries) {
    if (e.envelope.type !== 'ballot' || e.envelope.body.manifest !== manifestIndex) continue
    const b = e.envelope.body
    if (e.index > firstReveal) { issues.push({ severity: 'warning', entry: e.index, message: 'Ballot appended after the stage closed; ignored.' }); continue }
    const problem = await ballotProblem(b, m, verifyProof)
    if (problem) { issues.push({ severity: 'error', entry: e.index, message: `Invalid ballot: ${problem}` }); continue }
    finals.set(`${b.scope}|${b.nullifier}`, e)
  }

  // This stage's ballots only; rows naming earlier stages' ballots are re-reveals, handled by the caller.
  const byIdx = new Map(entries.map((e) => [e.index, e.envelope]))
  const ownBallot = (index: number) => byIdx.get(index)?.type === 'ballot' && byIdx.get(index)!.body.manifest === manifestIndex
  const revealed = new Map<number, Record<string, RevealedField>>()
  const undecryptable = new Set<number>()
  for (const r of reveals) {
    for (const row of r.envelope.body.rows) {
      if (!ownBallot(row.ballot)) continue
      if (row.undecryptable) undecryptable.add(row.ballot)
      else revealed.set(row.ballot, row.fields)
    }
  }

  const out: CountedRow[] = []
  const finalIndexes = new Set([...finals.values()].map((e) => e.index))
  for (const ballotIndex of [...revealed.keys(), ...undecryptable]) {
    if (!finalIndexes.has(ballotIndex)) issues.push({ severity: 'error', entry: ballotIndex, message: 'A ballot that is not the final ballot of its scope was revealed.' })
  }
  for (const [key, e] of finals) {
    const b = e.envelope.body
    if (b.rowType === 'full') continue
    if (undecryptable.has(e.index)) { stats.undecryptable++; continue }
    const fields = revealed.get(e.index)
    if (!fields) {
      if (reveals.length) issues.push({ severity: 'error', entry: e.index, message: 'A counted ballot was not revealed.' })
      continue
    }
    let ok = true
    for (const [field, f] of Object.entries(fields)) {
      if (!(await opensCommitment(b.commitments, field, f))) { ok = false; issues.push({ severity: 'error', entry: e.index, message: `Revealed ${field} does not open its commitment.` }) }
    }
    const choice = fields.choice
    const carry = fields.carry
    if (!choice || 'withheld' in choice || typeof choice.value !== 'string' || !(m.choices as string[]).includes(choice.value)) { ok = false; issues.push({ severity: 'error', entry: e.index, message: 'Choice missing, withheld or not one of the manifest choices.' }) }
    if (!carry || 'withheld' in carry || typeof carry.value !== 'boolean') { ok = false; issues.push({ severity: 'error', entry: e.index, message: 'Carry flag missing or withheld.' }) }
    if (!ok) continue
    out.push({
      ballot: e.index,
      rowType: b.rowType,
      ...(b.dimension ? { dimension: b.dimension } : {}),
      key,
      fields,
      choice: (choice as { value: string }).value,
      carry: (carry as { value: boolean }).value,
      manifest: manifestIndex,
    })
  }
  return out
}

async function ballotProblem(b: Record<string, any>, m: Record<string, any>, verifyProof?: (b: Record<string, any>) => Promise<boolean>): Promise<string | null> {
  if (!(m.franchises as string[]).includes(b.franchise)) return 'franchise not in the manifest'
  if (m.groupRoots[b.franchise]?.root !== b.groupRoot) return 'group root is not the one frozen in the manifest'
  if (m.groupRoots[b.franchise]?.depth !== b.proof.merkleTreeDepth) return 'proof depth is not the one fixed for the franchise'
  const expectedScope = b.rowType === 'main' ? `bill:${m.billKey}` : b.rowType === 'demographic' ? `bill:${m.billKey}/dim:${b.dimension}` : `bill:${m.billKey}/full`
  if (b.scope !== expectedScope) return `scope should be ${expectedScope}`
  if (b.rowType === 'demographic' && m.dimensions && !(m.dimensions as string[]).includes(b.dimension)) return 'dimension not in the manifest'
  if (b.ciphertext.keyId !== m.encryption.keyId) return 'encrypted to the wrong key'
  if ((await ballotMessage(b.commitments, b.ciphertext.ct)) !== b.message) return 'message does not bind the commitments and ciphertext'
  if (verifyProof && !(await verifyProof(b))) return 'membership proof does not verify'
  return null
}

function sameTables(published: CountTable[], recounted: CountTable[]): boolean {
  const norm = (ts: CountTable[]) =>
    ts
      .map((t) => canonicalize({ ...t, rows: [...t.rows].sort((a, b) => String(a.value).localeCompare(String(b.value))) }))
      .sort()
  return canonicalize(norm(published)) === canonicalize(norm(recounted))
}
