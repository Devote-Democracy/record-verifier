import { equalBytes } from './bytes.ts'
import { nodeHash, sha256 } from './hash.ts'

/**
 * RFC 9162 (Certificate Transparency v2) Merkle tree hashing, proofs and proof
 * verification over leaf hashes. The log is C2SP tlog-tiles, which uses the same tree.
 */

const largestPowerOfTwoBelow = (n: number) => {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** MTH(D[n]) from the leaf hashes. The empty tree's root is SHA-256 of nothing. */
export async function rootHash(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array())
  if (leaves.length === 1) return leaves[0]!
  const k = largestPowerOfTwoBelow(leaves.length)
  return nodeHash(await rootHash(leaves.slice(0, k)), await rootHash(leaves.slice(k)))
}

/** PATH(m, D[n]): the audit path for leaf m. */
export async function inclusionProof(m: number, leaves: Uint8Array[]): Promise<Uint8Array[]> {
  if (m < 0 || m >= leaves.length) throw new RangeError('leaf index out of range')
  if (leaves.length === 1) return []
  const k = largestPowerOfTwoBelow(leaves.length)
  return m < k
    ? [...(await inclusionProof(m, leaves.slice(0, k))), await rootHash(leaves.slice(k))]
    : [...(await inclusionProof(m - k, leaves.slice(k))), await rootHash(leaves.slice(0, k))]
}

/** PROOF(m, D[n]): the consistency proof from the tree of size m to the tree of size n. */
export async function consistencyProof(m: number, leaves: Uint8Array[]): Promise<Uint8Array[]> {
  if (m < 0 || m > leaves.length) throw new RangeError('size out of range')
  if (m === 0 || m === leaves.length) return []
  return subproof(m, leaves, true)
}

async function subproof(m: number, leaves: Uint8Array[], b: boolean): Promise<Uint8Array[]> {
  if (m === leaves.length) return b ? [] : [await rootHash(leaves)]
  const k = largestPowerOfTwoBelow(leaves.length)
  return m <= k
    ? [...(await subproof(m, leaves.slice(0, k), b)), await rootHash(leaves.slice(k))]
    : [...(await subproof(m - k, leaves.slice(k), false)), await rootHash(leaves.slice(0, k))]
}

/** RFC 9162 section 2.1.3.2. */
export async function verifyInclusion(leafIndex: number, treeSize: number, leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): Promise<boolean> {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return false
  let fn = leafIndex
  let sn = treeSize - 1
  let r = leaf
  for (const p of proof) {
    if (sn === 0) return false
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r)
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2) }
      }
    } else {
      r = await nodeHash(r, p)
    }
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }
  return sn === 0 && equalBytes(r, root)
}

/** RFC 9162 section 2.1.4.2. */
export async function verifyConsistency(first: number, second: number, proof: Uint8Array[], firstRoot: Uint8Array, secondRoot: Uint8Array): Promise<boolean> {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 0 || first > second) return false
  if (first === second) return proof.length === 0 && equalBytes(firstRoot, secondRoot)
  if (first === 0) return proof.length === 0
  if (proof.length === 0) return false
  const path = (first & (first - 1)) === 0 ? [firstRoot, ...proof] : [...proof]
  let fn = first - 1
  let sn = second - 1
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2) }
  let fr = path[0]!
  let sr = path[0]!
  for (const c of path.slice(1)) {
    if (sn === 0) return false
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr)
      sr = await nodeHash(c, sr)
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2) }
      }
    } else {
      sr = await nodeHash(sr, c)
    }
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }
  return sn === 0 && equalBytes(fr, firstRoot) && equalBytes(sr, secondRoot)
}
