import assert from 'node:assert/strict'
import { test } from 'node:test'
import { concat, toBase64 } from '../src/bytes.ts'
import { canonicalBytes, utf8 } from '../src/canonical.ts'
import { leafHash } from '../src/hash.ts'
import { rootHash } from '../src/merkle.ts'
import { noteKeyId, parseVerifierKey, verifierKeyString } from '../src/note.ts'
import { buildEntryBundle, entryBundlePath, readLog, tileIndexPath, TILE_WIDTH } from '../src/tiles.ts'

test('tile index paths follow tlog-tiles', () => {
  assert.equal(tileIndexPath(0), '000')
  assert.equal(tileIndexPath(5), '005')
  assert.equal(tileIndexPath(1000), 'x001/000')
  assert.equal(tileIndexPath(1234067), 'x001/x234/067')
  assert.equal(entryBundlePath(1, TILE_WIDTH), 'tile/entries/001')
  assert.equal(entryBundlePath(2, 17), 'tile/entries/002.p/17')
})

test('readLog downloads bundles, checks canonical entries and the signed root', async () => {
  const origin = 'record.devotedemocracy.com/log/v1'
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const n = TILE_WIDTH + 3
  const entries = Array.from({ length: n }, (_, i) => canonicalBytes({ v: 1, type: 'appBuild', body: { platform: 'ios', version: '1.0.0', build: String(i), sha256: 'a'.repeat(64) } }))
  const root = await rootHash(await Promise.all(entries.map((e) => leafHash(e))))
  const text = `${origin}\n${n}\n${toBase64(root)}\n`
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, utf8(text)))
  const note = `${text}\n— ${origin} ${toBase64(concat(await noteKeyId(origin, pub), sig))}\n`
  const files: Record<string, Uint8Array> = {
    checkpoint: utf8(note),
    [entryBundlePath(0, TILE_WIDTH)]: buildEntryBundle(entries.slice(0, TILE_WIDTH)),
    [entryBundlePath(1, 3)]: buildEntryBundle(entries.slice(TILE_WIDTH)),
  }
  const fetcher = async (path: string) => { const f = files[path]; if (!f) throw new Error(`404 ${path}`); return f }
  const key = await parseVerifierKey(await verifierKeyString(origin, pub))
  const log = await readLog(fetcher, key, origin)
  assert.equal(log.entries.length, n)
  assert.equal(log.entries[TILE_WIDTH + 1]!.envelope.body.build, String(TILE_WIDTH + 1))
  files[entryBundlePath(1, 3)] = buildEntryBundle([...entries.slice(TILE_WIDTH, TILE_WIDTH + 2), canonicalBytes({ v: 1, type: 'appBuild', body: { platform: 'ios', version: '6.6.6', build: 'x', sha256: 'b'.repeat(64) } })])
  await assert.rejects(readLog(fetcher, key, origin), /signed root/)
})
