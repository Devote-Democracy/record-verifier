import { fromBase64 } from './bytes.ts'
import { parseEntry, type Envelope } from './envelope.ts'
import { leafHash } from './hash.ts'
import { rootHash } from './merkle.ts'
import { verifyCheckpoint, type Checkpoint, type Verifier } from './note.ts'
import { equalBytes } from './bytes.ts'
import type { LoggedEntry } from './recount.ts'

/**
 * A reader for a C2SP tlog-tiles log served over HTTP(S): the checkpoint, and entry
 * bundles at tile/entries/<N>[.p/<W>], each a sequence of (uint16 big-endian length, entry).
 * Entries are fetched in full and the root recomputed, which suits the record's size for
 * now; hash tiles and partial proofs can come later without changing callers.
 */
export const TILE_WIDTH = 256

/** tlog-tiles index encoding: 1234067 -> x001/x234/067. */
export function tileIndexPath(n: number): string {
  const groups: string[] = []
  let rest = n
  do {
    groups.unshift(String(rest % 1000).padStart(3, '0'))
    rest = Math.floor(rest / 1000)
  } while (rest > 0)
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join('/')
}

export function entryBundlePath(tile: number, width: number): string {
  return `tile/entries/${tileIndexPath(tile)}${width < TILE_WIDTH ? `.p/${width}` : ''}`
}

export function parseEntryBundle(bytes: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  let at = 0
  while (at < bytes.length) {
    if (at + 2 > bytes.length) throw new Error('truncated entry bundle')
    const len = (bytes[at]! << 8) | bytes[at + 1]!
    at += 2
    if (at + len > bytes.length) throw new Error('truncated entry in bundle')
    out.push(bytes.subarray(at, at + len))
    at += len
  }
  return out
}

export type Fetcher = (path: string) => Promise<Uint8Array>

/** A fetcher for a base URL (for example the public bucket or an Arweave gateway mirror). */
export function httpFetcher(baseUrl: string): Fetcher {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`
  return async (path) => {
    const res = await fetch(base + path)
    if (!res.ok) throw new Error(`GET ${path}: ${res.status}`)
    return new Uint8Array(await res.arrayBuffer())
  }
}

export type LogSnapshot = { checkpoint: Checkpoint; noteText: string; entries: LoggedEntry[]; leafHashes: Uint8Array[] }

/**
 * Downloads the checkpoint and every entry up to its size, checks the signature, checks each
 * entry is canonical and valid, and checks the entries hash to the signed root.
 */
export async function readLog(fetcher: Fetcher, logKey: Verifier, origin: string): Promise<LogSnapshot> {
  const noteText = new TextDecoder().decode(await fetcher('checkpoint'))
  const checkpoint = await verifyCheckpoint(noteText, logKey, origin)
  const raw: Uint8Array[] = []
  const fullTiles = Math.floor(checkpoint.size / TILE_WIDTH)
  for (let t = 0; t < fullTiles; t++) raw.push(...parseEntryBundle(await fetcher(entryBundlePath(t, TILE_WIDTH))))
  const partial = checkpoint.size % TILE_WIDTH
  if (partial) raw.push(...parseEntryBundle(await fetcher(entryBundlePath(fullTiles, partial))))
  if (raw.length !== checkpoint.size) throw new Error(`log has ${raw.length} entries, checkpoint says ${checkpoint.size}`)
  const leafHashes = await Promise.all(raw.map((e) => leafHash(e)))
  if (!equalBytes(await rootHash(leafHashes), checkpoint.rootHash)) throw new Error('entries do not hash to the signed root')
  const entries = raw.map((bytes, index) => ({ index, envelope: parseEntry(bytes) as Envelope }))
  return { checkpoint, noteText, entries, leafHashes }
}

export const decodeRootHash = (b64: string) => fromBase64(b64)

/** Builds an entry bundle (the inverse of parseEntryBundle); also used by tests and writers. */
export function buildEntryBundle(entries: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(entries.reduce((n, e) => n + 2 + e.length, 0))
  let at = 0
  for (const e of entries) {
    if (e.length > 0xffff) throw new RangeError('entry longer than 65535 bytes')
    out[at] = e.length >> 8
    out[at + 1] = e.length & 0xff
    out.set(e, at + 2)
    at += 2 + e.length
  }
  return out
}
