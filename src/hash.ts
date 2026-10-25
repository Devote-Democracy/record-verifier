import { concat } from './bytes.ts'

const subtle = globalThis.crypto.subtle

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data as BufferSource))
}

const LEAF = new Uint8Array([0x00])
const NODE = new Uint8Array([0x01])

/** RFC 9162 leaf hash: SHA-256(0x00 || entry). */
export const leafHash = (entry: Uint8Array) => sha256(concat(LEAF, entry))
/** RFC 9162 interior node: SHA-256(0x01 || left || right). */
export const nodeHash = (left: Uint8Array, right: Uint8Array) => sha256(concat(NODE, left, right))
