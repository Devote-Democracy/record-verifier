import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { Group } from '@semaphore-protocol/group'
import { Identity } from '@semaphore-protocol/identity'
import { generateProof } from '@semaphore-protocol/proof'
import { toBase64Url } from '../src/bytes.ts'
import { ballotMessage } from '../src/commitment.ts'
import { semaphoreMessage, semaphoreScope, verifyBallotProof } from '../src/semaphore.ts'

// snarkjs keeps a bn128 curve with worker threads alive; release it so the test process exits.
after(async () => { await (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128?.terminate() })

test('a real Semaphore v4 proof verifies for its ballot, and fails when the ballot is altered', { timeout: 300_000 }, async () => {
  const members = [new Identity(), new Identity(), new Identity()]
  const group = new Group(members.map((m) => m.commitment))
  const ct = toBase64Url(crypto.getRandomValues(new Uint8Array(64)))
  const message = await ballotMessage({ choice: { value: 'a'.repeat(64) } }, ct)
  const scope = 'bill:gb-hoc-bill-123'
  const proof = await generateProof(members[1]!, group, semaphoreMessage(message), await semaphoreScope(scope))
  const ballot = { scope, message, groupRoot: proof.merkleTreeRoot, nullifier: proof.nullifier, proof: { merkleTreeDepth: proof.merkleTreeDepth, points: proof.points } }
  assert.equal(await verifyBallotProof(ballot), true)
  assert.equal(await verifyBallotProof({ ...ballot, message: 'b'.repeat(64) }), false)
  assert.equal(await verifyBallotProof({ ...ballot, scope: 'bill:another' }), false)
  assert.equal(await verifyBallotProof({ ...ballot, nullifier: '1' }), false)
})
