import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toBase64Url } from '../src/bytes.ts'
import { ballotMessage, commitment } from '../src/commitment.ts'
import { validateEnvelope, type Envelope } from '../src/envelope.ts'
import { recountStage, type LoggedEntry } from '../src/recount.ts'
import { checkDisclosure } from '../src/disclosure.ts'

const BILL = 'gb-hoc-bill-123'
const ROOT = '123456789'
const KEY = 'stage-key-1'
const LADDERS = { area: ['constituency', 'region', 'nation'], ethnicity: ['detailed', 'broad'] }

function manifest(stageId: string, carryFrom: string[] = [], k = 2, l = 2): Envelope {
  return {
    v: 1,
    type: 'manifest',
    schemes: { admission: 'devote-issued-v1', membership: 'semaphore-v4', encryption: 'hpke-xwing-v1', tally: 'reveal-and-count-v1', disclosure: 'sdc-kl-v1' },
    body: {
      stageId,
      billKey: BILL,
      legislation: { id: 'gb-bill-123', jurisdiction: 'gb', title: 'Example Bill' },
      stage: { id: stageId, label: stageId },
      opensAt: '2026-11-01T09:00Z',
      closesAt: '2026-11-08T09:00Z',
      choices: ['aye', 'no', 'abstain'],
      franchises: ['gb-ukparl'],
      groupRoots: { 'gb-ukparl': { root: ROOT, size: 6, depth: 10 } },
      encryption: { keyId: KEY, publicKey: 'AAAA' },
      disclosure: { k, l, ladders: LADDERS },
      dimensions: ['ethnicity'],
      admissionKeys: [{ keyId: 'devote-admission-1', publicKey: 'AAAA' }],
      carryFrom,
      retentionUntil: '2028-11-08T09:00Z',
    },
  }
}

type Secret = { values: Record<string, Record<string, string | boolean>>; salts: Record<string, Record<string, Uint8Array>> }

async function ballot(manifestIndex: number, rowType: 'main' | 'demographic', nullifier: string, values: Record<string, Record<string, string | boolean>>, dimension?: string): Promise<{ env: Envelope; secret: Secret }> {
  const commitments: Record<string, Record<string, string>> = {}
  const salts: Secret['salts'] = {}
  for (const [field, levels] of Object.entries(values)) {
    commitments[field] = {}
    salts[field] = {}
    for (const [level, value] of Object.entries(levels)) {
      const salt = crypto.getRandomValues(new Uint8Array(32))
      salts[field]![level] = salt
      commitments[field]![level] = await commitment(field, level, value, salt)
    }
  }
  const ct = toBase64Url(crypto.getRandomValues(new Uint8Array(64)))
  const body: Record<string, unknown> = {
    manifest: manifestIndex,
    rowType,
    scope: rowType === 'main' ? `bill:${BILL}` : `bill:${BILL}/dim:${dimension}`,
    franchise: 'gb-ukparl',
    groupRoot: ROOT,
    nullifier,
    message: await ballotMessage(commitments, ct),
    proof: { merkleTreeDepth: 10, points: Array(8).fill('1') },
    commitments,
    ciphertext: { keyId: KEY, enc: 'AAAA', ct },
  }
  if (dimension) body.dimension = dimension
  return { env: { v: 1, type: 'ballot', body }, secret: { values, salts } }
}

const main = (choice: string, carry: boolean, constituency: string, region: string) => ({ choice: { value: choice }, carry: { value: carry }, area: { constituency, region, nation: 'E92000001' } })
const demo = (choice: string, carry: boolean, detailed: string, broad: string) => ({ choice: { value: choice }, carry: { value: carry }, value: { detailed, broad } })

function revealRow(index: number, secret: Secret, levels: Record<string, string | null>) {
  const fields: Record<string, unknown> = {}
  for (const [field, level] of Object.entries(levels)) {
    if (level === null) { fields[field] = { withheld: true }; continue }
    fields[field] = { level, value: secret.values[field]![level], salt: toBase64Url(secret.salts[field]![level]!) }
  }
  return { ballot: index, fields }
}

async function buildStage() {
  const log: LoggedEntry[] = []
  const add = (envelope: Envelope) => { const r = validateEnvelope(envelope); assert.ok(r.ok, JSON.stringify((r as { errors?: string[] }).errors)); log.push({ index: log.length, envelope }); return log.length - 1 }
  const m = add(manifest('s1'))
  const secrets = new Map<number, Secret>()
  const cast = async (rowType: 'main' | 'demographic', nullifier: string, values: Record<string, Record<string, string | boolean>>, dim?: string) => {
    const b = await ballot(m, rowType, nullifier, values, dim)
    const i = add(b.env)
    secrets.set(i, b.secret)
    return i
  }
  // Six voters in two regions; voter 1 changes their mind.
  const superseded = await cast('main', '101', main('aye', true, 'E14000001', 'E12000001'))
  const finals = [
    await cast('main', '101', main('no', true, 'E14000001', 'E12000001')),
    await cast('main', '102', main('aye', true, 'E14000002', 'E12000001')),
    await cast('main', '103', main('aye', false, 'E14000003', 'E12000001')),
    await cast('main', '104', main('no', true, 'E14000004', 'E12000002')),
    await cast('main', '105', main('aye', true, 'E14000005', 'E12000002')),
    await cast('main', '106', main('abstain', true, 'E14000006', 'E12000002')),
  ]
  const demos = [
    await cast('demographic', '201', demo('no', true, 'indian', 'asian'), 'ethnicity'),
    await cast('demographic', '202', demo('aye', true, 'pakistani', 'asian'), 'ethnicity'),
    await cast('demographic', '203', demo('aye', false, 'white-british', 'white'), 'ethnicity'),
    await cast('demographic', '204', demo('no', true, 'white-irish', 'white'), 'ethnicity'),
  ]
  return { log, add, m, secrets, superseded, finals, demos }
}

async function closeStage(s: Awaited<ReturnType<typeof buildStage>>, opts: { extraReveal?: number } = {}) {
  const rows = [
    ...s.finals.map((i) => revealRow(i, s.secrets.get(i)!, { choice: 'value', carry: 'value', area: 'region' })),
    ...s.demos.map((i) => revealRow(i, s.secrets.get(i)!, { choice: 'value', carry: 'value', value: 'broad' })),
  ]
  if (opts.extraReveal !== undefined) rows.push(revealRow(opts.extraReveal, s.secrets.get(opts.extraReveal)!, { choice: 'value', carry: 'value', area: 'region' }))
  const revealIndex = s.add({ v: 1, type: 'reveal', body: { manifest: s.m, rows } })
  return revealIndex
}

const tables = [
  { rowType: 'main', field: 'area', level: 'region', rows: [{ value: 'E12000001', counts: { no: 1, aye: 2 } }, { value: 'E12000002', counts: { no: 1, aye: 1, abstain: 1 } }] },
  { rowType: 'demographic', dimension: 'ethnicity', field: 'value', level: 'broad', rows: [{ value: 'asian', counts: { no: 1, aye: 1 } }, { value: 'white', counts: { aye: 1, no: 1 } }] },
]
const report = { k: 2, l: 2, rowsCounted: 10, fieldsGeneralised: 10, fieldsWithheld: 0 }

test('a stage recounts, matches its tally, and ignores the superseded ballot', async () => {
  const s = await buildStage()
  const reveal = await closeStage(s)
  s.add({ v: 1, type: 'tally', body: { manifest: s.m, reveals: [reveal], totals: { aye: 3, no: 2, abstain: 1 }, tables, disclosureReport: report } })
  const r = await recountStage(s.log, s.m)
  assert.deepEqual(r.totals, { aye: 3, no: 2, abstain: 1 })
  assert.equal(r.tallyMatches, true)
  assert.deepEqual(r.disclosureViolations, [])
  assert.deepEqual(r.issues.filter((i) => i.severity === 'error'), [])
})

test('a doctored tally is caught', async () => {
  const s = await buildStage()
  const reveal = await closeStage(s)
  s.add({ v: 1, type: 'tally', body: { manifest: s.m, reveals: [reveal], totals: { aye: 4, no: 1, abstain: 1 }, tables, disclosureReport: report } })
  const r = await recountStage(s.log, s.m)
  assert.equal(r.tallyMatches, false)
})

test('revealing a superseded ballot is an error', async () => {
  const s = await buildStage()
  await closeStage(s, { extraReveal: s.superseded })
  const r = await recountStage(s.log, s.m)
  assert.ok(r.issues.some((i) => i.severity === 'error' && i.message.includes('not the final ballot')))
})

test('a dropped ballot is an error', async () => {
  const s = await buildStage()
  const rows = s.finals.slice(1).map((i) => revealRow(i, s.secrets.get(i)!, { choice: 'value', carry: 'value', area: 'region' }))
  s.add({ v: 1, type: 'reveal', body: { manifest: s.m, rows } })
  const r = await recountStage(s.log, s.m)
  assert.ok(r.issues.some((i) => i.message.includes('was not revealed')))
})

test('publishing at constituency level breaks the k rule', async () => {
  const s = await buildStage()
  const rows = s.finals.map((i) => revealRow(i, s.secrets.get(i)!, { choice: 'value', carry: 'value', area: 'constituency' }))
  s.add({ v: 1, type: 'reveal', body: { manifest: s.m, rows } })
  const r = await recountStage(s.log, s.m)
  assert.ok(r.disclosureViolations.length > 0)
  assert.ok(r.disclosureViolations.every((v) => v.rule === 'k'))
})

test('a unanimous group breaks the l rule', () => {
  const qis = { area: { level: 'region', value: 'E12000001' } }
  const rows = [0, 1, 2].map(() => ({ rowType: 'main' as const, choice: 'aye', qis }))
  const v = checkDisclosure(rows, 2, 2)
  assert.equal(v.length, 1)
  assert.equal(v[0]!.rule, 'l')
  assert.deepEqual(checkDisclosure([...rows, { rowType: 'main', choice: 'no', qis }], 2, 2), [])
})

test('carried votes count at the next stage unless the voter votes again', async () => {
  const s = await buildStage()
  await closeStage(s)
  const m2 = s.add(manifest('s2', ['s1']))
  // Voter 2 (n2) votes again at stage 2: from aye to no, at region E12000001.
  const b = await ballot(m2, 'main', '102', main('no', true, 'E14000002', 'E12000001'))
  const i = s.add(b.env)
  s.add({ v: 1, type: 'reveal', body: { manifest: m2, rows: [revealRow(i, b.secret, { choice: 'value', carry: 'value', area: 'region' })] } })
  const r = await recountStage(s.log, m2)
  // Stage 1 carried rows: n1 no, n4 no, n5 aye, n6 abstain (n3 had carry=false). Plus n2 no now.
  assert.deepEqual(r.totals, { aye: 1, no: 3, abstain: 1 })
  // Carried: main n1, n4, n5, n6 and demographic d1, d2, d4 (n3 and d3 had carry=false).
  assert.equal(r.carriedRows, 7)
  assert.equal(r.tallyMatches, null)
})
