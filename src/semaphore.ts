import { verifyProof } from '@semaphore-protocol/proof'
import { toHex } from './bytes.ts'
import { utf8 } from './canonical.ts'
import { sha256 } from './hash.ts'

/**
 * Semaphore v4 membership-proof check for ballots (SPEC.md section 6), for recountStage's
 * `verifyProof` option. A separate entry point (`@devotedemocracy/record-verifier/semaphore`)
 * because it brings snarkjs and the Groth16 verification keys.
 */
export async function semaphoreScope(scope: string): Promise<bigint> {
  return BigInt(`0x${toHex(await sha256(utf8(scope)))}`)
}

export const semaphoreMessage = (messageHex: string): bigint => BigInt(`0x${messageHex}`)

export async function verifyBallotProof(ballot: Record<string, any>): Promise<boolean> {
  try {
    return await verifyProof({
      merkleTreeDepth: ballot.proof.merkleTreeDepth,
      merkleTreeRoot: ballot.groupRoot,
      nullifier: ballot.nullifier,
      message: semaphoreMessage(ballot.message).toString(),
      scope: (await semaphoreScope(ballot.scope)).toString(),
      points: ballot.proof.points,
    } as Parameters<typeof verifyProof>[0])
  } catch {
    return false
  }
}

/** snarkjs keeps worker threads alive after verifying; call this when done in Node so the process can exit. */
export async function releaseSemaphore(): Promise<void> {
  await (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128?.terminate()
}
