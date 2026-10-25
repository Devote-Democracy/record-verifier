import { Ajv2020 } from 'ajv/dist/2020.js'
import schema from '../schemas/record-v1.schema.json' with { type: 'json' }
import { canonicalBytes } from './canonical.ts'
import { leafHash } from './hash.ts'

/** A log entry. Bodies are typed loosely here; the schema is the authority (SPEC.md section 4). */
export type EntryType = 'manifest' | 'admission' | 'revocation' | 'ballot' | 'reveal' | 'tally' | 'snapshot' | 'query' | 'audit' | 'appBuild' | 'anchor'
export type Envelope = { v: 1; type: EntryType; schemes?: Record<string, string | string[]>; body: Record<string, any> }

const ajv = new Ajv2020({ allErrors: true, strict: false })
const validate = ajv.compile(schema)

export function validateEnvelope(value: unknown): { ok: true; envelope: Envelope } | { ok: false; errors: string[] } {
  if (validate(value)) return { ok: true, envelope: value as Envelope }
  return { ok: false, errors: (validate.errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message ?? 'is invalid'}`) }
}

/** The bytes stored as the log entry. */
export const entryBytes = (envelope: Envelope) => canonicalBytes(envelope)
export const entryLeafHash = (envelope: Envelope) => leafHash(entryBytes(envelope))

/** Parses entry bytes as stored in the log; they must already be canonical. */
export function parseEntry(bytes: Uint8Array): Envelope {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  const value = JSON.parse(text)
  const result = validateEnvelope(value)
  if (!result.ok) throw new Error(`invalid entry: ${result.errors.join('; ')}`)
  const again = new TextDecoder().decode(canonicalBytes(value))
  if (again !== text) throw new Error('entry is not in canonical form')
  return result.envelope
}
