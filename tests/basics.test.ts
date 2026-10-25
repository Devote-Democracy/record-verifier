import assert from 'node:assert/strict'
import { test } from 'node:test'
import { canonicalize } from '../src/canonical.ts'
import { toBase64, toBase64Url, fromBase64Url, toHex } from '../src/bytes.ts'
import { leafHash } from '../src/hash.ts'
import { consistencyProof, inclusionProof, rootHash, verifyConsistency, verifyInclusion } from '../src/merkle.ts'
import { parseVerifierKey, verifierKeyString, verifyCheckpoint, noteKeyId } from '../src/note.ts'
import { commitment, opensCommitment } from '../src/commitment.ts'
import { concat } from '../src/bytes.ts'
import { utf8 } from '../src/canonical.ts'

test('JCS: RFC 8785 ordering, numbers and escaping', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'], c: { z: 1e21, y: 0.000001, x: -0 } }), '{"a":[true,null,"x"],"b":1,"c":{"x":0,"y":0.000001,"z":1e+21}}')
  assert.equal(canonicalize({ '\u20ac': 1, '\r': 2, '1': 3 }), '{"\\r":2,"1":3,"\u20ac":1}')
  assert.equal(canonicalize('a\u0001"\\'), '"a\\u0001\\"\\\\"')
  assert.throws(() => canonicalize(NaN))
  assert.throws(() => canonicalize('\uD800'))
})

test('base64url round trip', () => {
  const b = new Uint8Array([0, 255, 62, 63, 1])
  assert.deepEqual(fromBase64Url(toBase64Url(b)), b)
})

const leaves = (n: number) => Promise.all(Array.from({ length: n }, (_, i) => leafHash(utf8(`entry ${i}`))))

test('Merkle: every inclusion proof verifies, tampered ones fail', async () => {
  for (let n = 1; n <= 33; n++) {
    const ls = await leaves(n)
    const root = await rootHash(ls)
    for (let i = 0; i < n; i++) {
      const proof = await inclusionProof(i, ls)
      assert.ok(await verifyInclusion(i, n, ls[i]!, proof, root), `n=${n} i=${i}`)
      if (n > 1) assert.ok(!(await verifyInclusion((i + 1) % n, n, ls[i]!, proof, root)), `wrong index n=${n} i=${i}`)
    }
  }
})

test('Merkle: every consistency proof verifies, wrong roots fail', async () => {
  const all = await leaves(24)
  for (let n = 1; n <= 24; n++) {
    const second = await rootHash(all.slice(0, n))
    for (let m = 0; m <= n; m++) {
      const first = await rootHash(all.slice(0, m))
      const proof = await consistencyProof(m, all.slice(0, n))
      assert.ok(await verifyConsistency(m, n, proof, first, second), `m=${m} n=${n}`)
      if (m > 0 && m < n) assert.ok(!(await verifyConsistency(m, n, proof, second, second)), `bad first root m=${m} n=${n}`)
    }
  }
})

async function keyPair() {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  return { kp, pub }
}

export async function signNote(text: string, name: string, kp: CryptoKeyPair, pub: Uint8Array) {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, utf8(text)))
  return `${text}\n\u2014 ${name} ${toBase64(concat(await noteKeyId(name, pub), sig))}\n`
}

test('signed checkpoints verify with the log key only', async () => {
  const origin = 'record.devotedemocracy.com/log/v1'
  const { kp, pub } = await keyPair()
  const other = await keyPair()
  const ls = await leaves(5)
  const text = `${origin}\n5\n${toBase64(await rootHash(ls))}\n`
  const note = await signNote(text, origin, kp, pub)
  const vkey = await parseVerifierKey(await verifierKeyString(origin, pub))
  const cp = await verifyCheckpoint(note, vkey, origin)
  assert.equal(cp.size, 5)
  assert.equal(toHex(cp.rootHash), toHex(await rootHash(ls)))
  const wrong = await parseVerifierKey(await verifierKeyString(origin, other.pub))
  await assert.rejects(verifyCheckpoint(note, wrong, origin))
  await assert.rejects(verifyCheckpoint(note.replace('\n5\n', '\n6\n'), vkey, origin))
})

test('commitments open only with the right value, level and salt', async () => {
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const c = await commitment('area', 'region', 'E12000003', salt)
  const commitments = { area: { region: c } }
  assert.ok(await opensCommitment(commitments, 'area', { level: 'region', value: 'E12000003', salt: toBase64Url(salt) }))
  assert.ok(!(await opensCommitment(commitments, 'area', { level: 'region', value: 'E12000004', salt: toBase64Url(salt) })))
  assert.ok(!(await opensCommitment(commitments, 'area', { level: 'nation', value: 'E12000003', salt: toBase64Url(salt) })))
  assert.ok(await opensCommitment(commitments, 'area', { withheld: true }))
})
