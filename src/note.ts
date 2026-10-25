import { concat, equalBytes, fromBase64, toBase64, toHex } from './bytes.ts'
import { utf8 } from './canonical.ts'
import { sha256 } from './hash.ts'

/**
 * C2SP signed-note and tlog-checkpoint. A checkpoint note's text is:
 *   <origin>\n<tree size>\n<base64 root hash>\n[extension lines]\n
 * followed by a blank line and one or more signature lines:
 *   — <key name> <base64(4-byte key id || signature)>\n
 * Ed25519 keys (algorithm byte 0x01) are the only kind version 1 uses.
 */

const SIG_PREFIX = '— '
const ED25519 = 0x01

export type Verifier = { name: string; keyId: Uint8Array; publicKey: Uint8Array }

/** Parses a verifier key string: "<name>+<8 hex key id>+<base64(0x01 || 32-byte key)>". */
export async function parseVerifierKey(vkey: string): Promise<Verifier> {
  // The name and key id contain no '+'; the base64 key may.
  const first = vkey.indexOf('+')
  const second = vkey.indexOf('+', first + 1)
  if (first <= 0 || second < 0) throw new TypeError('verifier key must be name+keyid+key')
  const name = vkey.slice(0, first)
  const idHex = vkey.slice(first + 1, second)
  const keyB64 = vkey.slice(second + 1)
  const raw = fromBase64(keyB64)
  if (raw.length !== 33 || raw[0] !== ED25519) throw new TypeError('only Ed25519 verifier keys are supported')
  const keyId = await noteKeyId(name, raw.subarray(1))
  if (toHex(keyId) !== idHex.toLowerCase()) throw new TypeError('verifier key id does not match the key')
  return { name, keyId, publicKey: raw.subarray(1) }
}

/** Key id: the first 4 bytes of SHA-256(name || "\n" || 0x01 || public key). */
export async function noteKeyId(name: string, publicKey: Uint8Array): Promise<Uint8Array> {
  return (await sha256(concat(utf8(name), new Uint8Array([0x0a, ED25519]), publicKey))).subarray(0, 4)
}

export async function verifierKeyString(name: string, publicKey: Uint8Array): Promise<string> {
  return `${name}+${toHex(await noteKeyId(name, publicKey))}+${toBase64(concat(new Uint8Array([ED25519]), publicKey))}`
}

export type SignedNote = { text: string; signatures: { name: string; keyId: Uint8Array; signature: Uint8Array }[] }

export function parseNote(note: string): SignedNote {
  const split = note.lastIndexOf('\n\n')
  if (split < 0) throw new TypeError('note has no signature block')
  const text = note.slice(0, split + 1)
  const sigLines = note.slice(split + 2).split('\n').filter((l) => l !== '')
  if (sigLines.length === 0) throw new TypeError('note has no signatures')
  const signatures = sigLines.map((line) => {
    if (!line.startsWith(SIG_PREFIX)) throw new TypeError('bad signature line')
    const [name, b64] = line.slice(SIG_PREFIX.length).split(' ')
    if (!name || !b64) throw new TypeError('bad signature line')
    const raw = fromBase64(b64)
    if (raw.length < 5) throw new TypeError('signature too short')
    return { name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) }
  })
  return { text, signatures }
}

export async function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  const key = await globalThis.crypto.subtle.importKey('raw', publicKey as BufferSource, { name: 'Ed25519' }, false, ['verify'])
  return globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, signature as BufferSource, message as BufferSource)
}

/** True when at least one signature in the note is a valid signature by this verifier. */
export async function verifyNote(note: SignedNote, verifier: Verifier): Promise<boolean> {
  for (const s of note.signatures) {
    if (s.name !== verifier.name || !equalBytes(s.keyId, verifier.keyId)) continue
    if (await ed25519Verify(verifier.publicKey, s.signature, utf8(note.text))) return true
  }
  return false
}

export type Checkpoint = { origin: string; size: number; rootHash: Uint8Array; extensions: string[] }

export function parseCheckpoint(text: string): Checkpoint {
  const lines = text.split('\n')
  if (lines.at(-1) !== '') throw new TypeError('checkpoint text must end with a newline')
  const [origin, sizeText, rootB64, ...rest] = lines.slice(0, -1)
  if (!origin || !sizeText || !rootB64) throw new TypeError('checkpoint needs origin, size and root')
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) throw new TypeError('bad tree size')
  const size = Number(sizeText)
  if (!Number.isSafeInteger(size)) throw new TypeError('tree size too large')
  const rootHash = fromBase64(rootB64)
  if (rootHash.length !== 32) throw new TypeError('root hash must be 32 bytes')
  return { origin, size, rootHash, extensions: rest }
}

/**
 * Parses a signed checkpoint and checks the log's signature. Witness cosignatures
 * (C2SP tlog-cosignature) are reported but not required here.
 */
export async function verifyCheckpoint(noteText: string, logKey: Verifier, expectedOrigin?: string): Promise<Checkpoint> {
  const note = parseNote(noteText)
  if (!(await verifyNote(note, logKey))) throw new Error('checkpoint is not signed by the log key')
  const checkpoint = parseCheckpoint(note.text)
  if (expectedOrigin !== undefined && checkpoint.origin !== expectedOrigin) throw new Error(`checkpoint origin is ${checkpoint.origin}, expected ${expectedOrigin}`)
  return checkpoint
}

/** SPEC.md section 7: the value anchors commit to, SHA-256 of the checkpoint's signed text (no signatures). */
export async function anchorDigest(noteText: string): Promise<string> {
  return toHex(await sha256(utf8(parseNote(noteText).text)))
}
