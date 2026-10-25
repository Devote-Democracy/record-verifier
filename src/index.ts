/**
 * @devotedemocracy/record-verifier: check the Devote Public Record without trusting Devote.
 * See SPEC.md. Works in Node 22+ and modern browsers (WebCrypto, no Buffer).
 */
export { canonicalize, canonicalBytes } from './canonical.ts'
export { toHex, fromHex, toBase64, fromBase64, toBase64Url, fromBase64Url, equalBytes } from './bytes.ts'
export { sha256, leafHash, nodeHash } from './hash.ts'
export { rootHash, inclusionProof, consistencyProof, verifyInclusion, verifyConsistency } from './merkle.ts'
export { parseVerifierKey, verifierKeyString, noteKeyId, parseNote, verifyNote, parseCheckpoint, verifyCheckpoint, ed25519Verify, type Checkpoint, type Verifier, type SignedNote } from './note.ts'
export { commitment, ballotMessage, opensCommitment, signedPayload, verifySignedBody, type Commitments, type RevealedField, type FieldValue } from './commitment.ts'
export { validateEnvelope, entryBytes, entryLeafHash, parseEntry, type Envelope, type EntryType } from './envelope.ts'
export { checkDisclosure, type PublishedRow, type DisclosureViolation } from './disclosure.ts'
export { recountStage, type LoggedEntry, type StageRecount, type CountTable, type Issue } from './recount.ts'

export const LOG_ORIGIN = 'record.devotedemocracy.com/log/v1'
