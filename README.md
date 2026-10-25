# Devote Public Record verifier

Check the Devote Public Record ([record.devotedemocracy.com](https://record.devotedemocracy.com))
yourself, without trusting Devote.

Devote users vote on the stages of real legislation. Every admission of a voter, every anonymous ballot,
every published row and every result goes into one append-only log, anchored in Bitcoin and Ethereum.
This package is the **specification** of that record ([SPEC.md](SPEC.md)), its **JSON Schemas**
([schemas/](schemas/)) and a **verifier library**. It works in Node 22+ and in browsers.

## What you can check

| Check | Function |
|---|---|
| An entry is well formed and canonical | `parseEntry`, `validateEnvelope` |
| A checkpoint is signed by the log | `verifyCheckpoint` |
| An entry is in the log | `verifyInclusion` |
| The log never rewrote history between two checkpoints | `verifyConsistency` |
| A published value is the one committed during the vote | `opensCommitment` |
| An admission was signed by the stated issuer | `verifySignedBody` |
| A stage's result: supersession, carry, reveals, totals, tables | `recountStage` |
| No published group is small enough to identify anyone | `checkDisclosure` (inside `recountStage`) |

Membership proofs (Semaphore v4) are checked through the `verifyProof` option of `recountStage`. A
ready-made Semaphore verifier module and a command-line tool are coming in the next release.

## Example

```ts
import { parseVerifierKey, verifyCheckpoint, recountStage, LOG_ORIGIN } from '@devotedemocracy/record-verifier'

const logKey = await parseVerifierKey(PUBLISHED_LOG_KEY)          // from the site and this repo
const checkpoint = await verifyCheckpoint(noteText, logKey, LOG_ORIGIN)
const result = await recountStage(entries, manifestIndex)           // entries fetched from the tiles
console.log(result.totals, result.tallyMatches, result.issues)
```

## Develop

```bash
npm install
npm run check      # typecheck and tests
npm run build      # dist/
```

## Status

Draft 1 of the format, 2026-10-25. Nothing has been published to the log yet. The format may still
change until the first real vote; after that, changes come as new scheme ids or envelope versions
(SPEC.md section 12).

## Licence

Apache-2.0. Implement your own verifier from SPEC.md if you prefer: that is the point.
