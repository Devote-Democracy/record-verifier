#!/usr/bin/env node
/**
 * record-verify: check the Devote Public Record from the command line.
 *
 *   record-verify log      --base <url> --key <verifier key>
 *   record-verify recount  --base <url> --key <verifier key> --manifest <leaf index>
 *
 * --base is where the log's tiles are served (the record's public bucket or a mirror).
 * --key is the log's published verifier key (name+keyid+base64).
 */
import { parseArgs } from 'node:util'
import { LOG_ORIGIN, parseVerifierKey, recountStage } from '../src/index.ts'
import { httpFetcher, readLog } from '../src/tiles.ts'

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { base: { type: 'string' }, key: { type: 'string' }, manifest: { type: 'string' }, origin: { type: 'string' } },
})
const command = positionals[0]
if (!command || !values.base || !values.key || !['log', 'recount'].includes(command)) {
  console.error('usage: record-verify <log|recount> --base <url> --key <verifier key> [--manifest <index>] [--origin <origin>]')
  process.exit(2)
}

const logKey = await parseVerifierKey(values.key)
const log = await readLog(httpFetcher(values.base), logKey, values.origin ?? LOG_ORIGIN)
console.log(`Checkpoint verified: ${log.checkpoint.origin}, ${log.checkpoint.size} entries; every entry is canonical, valid and hashes to the signed root.`)

if (command === 'log') {
  const counts: Record<string, number> = {}
  for (const e of log.entries) counts[e.envelope.type] = (counts[e.envelope.type] ?? 0) + 1
  console.log('Entries by type:', counts)
  for (const e of log.entries.filter((x) => x.envelope.type === 'manifest')) {
    const b = e.envelope.body
    console.log(`  manifest #${e.index}: ${b.legislation.title} · ${b.stage.label} · ${b.opensAt} to ${b.closesAt}`)
  }
} else {
  const index = Number(values.manifest)
  if (!Number.isInteger(index)) { console.error('--manifest <leaf index> is required'); process.exit(2) }
  const r = await recountStage(log.entries, index)
  console.log('Totals:', r.totals)
  console.log(`Counted rows: ${r.countedRows} (${r.carriedRows} carried from earlier stages)`)
  console.log('Published tally matches the recount:', r.tallyMatches === null ? 'no tally yet' : r.tallyMatches)
  for (const i of r.issues) console.log(`  ${i.severity}${i.entry !== undefined ? ` (#${i.entry})` : ''}: ${i.message}`)
  process.exit(r.issues.some((i) => i.severity === 'error') ? 1 : 0)
}
