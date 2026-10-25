import { concat, fromBase64Url, toHex } from './bytes.ts'
import { canonicalize, utf8 } from './canonical.ts'
import { sha256 } from './hash.ts'
import { ed25519Verify } from './note.ts'

/** SPEC.md section 6: commitments, the message a proof binds, and signed admissions. */

const COMMIT_DOMAIN = utf8('devote-record/commit/v1')
const ZERO = new Uint8Array([0x00])

export type FieldValue = string | boolean

export async function commitment(field: string, level: string, value: FieldValue, salt: Uint8Array): Promise<string> {
  if (salt.length !== 32) throw new RangeError('salt must be 32 bytes')
  return toHex(await sha256(concat(COMMIT_DOMAIN, ZERO, utf8(canonicalize([field, level, value])), salt)))
}

export type Commitments = Record<string, Record<string, string>>

/** The value a ballot's Semaphore proof binds as its message. */
export async function ballotMessage(commitments: Commitments | undefined, ciphertextB64u: string): Promise<string> {
  const ctHash = toHex(await sha256(fromBase64Url(ciphertextB64u)))
  return toHex(await sha256(utf8(canonicalize({ commitments: commitments ?? {}, ciphertext: ctHash }))))
}

export type RevealedField = { level: string; value: FieldValue; salt: string } | { withheld: true }

/** True when the revealed value and salt open the ballot's commitment at that level. */
export async function opensCommitment(commitments: Commitments | undefined, field: string, revealed: RevealedField): Promise<boolean> {
  if ('withheld' in revealed) return true
  const expected = commitments?.[field]?.[revealed.level]
  if (!expected) return false
  return (await commitment(field, revealed.level, revealed.value, fromBase64Url(revealed.salt))) === expected
}

/** SPEC.md section 11: the bytes an admission or revocation signature covers. */
export function signedPayload(kind: 'admission' | 'revocation', body: Record<string, unknown>): Uint8Array {
  const { signatures: _omit, ...rest } = body
  return concat(utf8(`devote-record/${kind}/v1`), ZERO, utf8(canonicalize(rest)))
}

export async function verifySignedBody(kind: 'admission' | 'revocation', body: Record<string, unknown> & { signatures: { keyId: string; sig: string }[] }, keys: { keyId: string; publicKey: string }[]): Promise<boolean> {
  const payload = signedPayload(kind, body)
  for (const s of body.signatures) {
    const key = keys.find((k) => k.keyId === s.keyId)
    if (key && (await ed25519Verify(fromBase64Url(key.publicKey), fromBase64Url(s.sig), payload))) return true
  }
  return false
}
