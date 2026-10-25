# The Devote Public Record: format and verification, version 1

Status: **draft 1**, 2026-10-25. This document is the single definition of the record's format.
Devote's own services, and anyone who wants to check Devote, implement from it. The JSON Schemas in
`schemas/` are normative for entry shapes; this text is normative for everything else.

Key words: MUST, SHOULD and MAY are used as in RFC 2119.

## 1. What the record is

Devote users vote on stages of legislation. The record lets anyone check, without trusting Devote:

1. **Nothing was altered or dropped.** Every entry is in one append-only Merkle log. Its checkpoints
   are countersigned by witnesses and anchored in Bitcoin and Ethereum.
2. **The results add up.** Every counted ballot is published at close, with commitments made during
   the vote, and anyone can recount.
3. **Every ballot came from an admitted elector, at most once per scope.** Each ballot carries an
   anonymous membership proof and a nullifier.
4. **No published ballot identifies anyone.** Published rows meet the disclosure rules stated in the
   stage's manifest, and anyone can check that.

The record never contains names, account ids, network addresses or per-ballot timestamps.

## 2. The log

- The log follows **C2SP tlog-tiles**: tiles and entry bundles served as static files.
- Its **origin** is `record.devotedemocracy.com/log/v1`.
- Each log entry is the **canonical JSON** (section 3) of one envelope, encoded as UTF-8.
- **Leaf hash:** `SHA-256(0x00 || entry)`. **Interior node:** `SHA-256(0x01 || left || right)`,
  as in RFC 9162.
- **Checkpoints** are C2SP tlog-checkpoint signed notes, signed by the log key (Ed25519) under the key
  name equal to the origin.
- **Witnesses** add cosignatures per C2SP tlog-cosignature.
- **Anchors** (section 7) fix checkpoints in public chains.
- Verifiers MUST check:
  - inclusion proofs for entries they rely on;
  - consistency proofs between every pair of checkpoints they have seen.

## 3. Canonical JSON

Entries are serialised with **RFC 8785 (JSON Canonicalization Scheme)**:
- object members sorted by UTF-16 code units;
- no insignificant whitespace;
- numbers in ECMAScript shortest form;
- strings with the minimal escaping of RFC 8785.

Integers that may exceed 2^53 (for example field elements and nullifiers) are carried as **decimal
strings**. Binary values are **lowercase hex** (hashes) or **base64url without padding** (keys,
ciphertexts, signatures), as each schema field says.

## 4. Envelope

```json
{ "v": 1, "type": "<entry type>", "schemes": { "<port>": "<scheme id>" }, "body": { } }
```

- `v` MUST be `1`.
- `schemes` is required on `manifest` entries and optional elsewhere.
- A verifier that meets an unknown `type` or scheme id MUST report it rather than skip it.

### Entry types

| type | Written | What it holds |
|---|---|---|
| `manifest` | when a stage opens | The stage's rules, schemes, choices, frozen group roots, encryption key, disclosure rules |
| `admission` | when a credential is admitted | A credential commitment joining a franchise group, with the issuer's signature |
| `revocation` | when a credential is retired | Stops a commitment voting from the next manifest on |
| `ballot` | as ballots arrive, in batches | One anonymous row: commitments, ciphertext, membership proof, nullifier |
| `reveal` | at close | The published value and salt of each counted ballot's fields, at the level disclosure control allowed |
| `tally` | at close | Results, tables and the disclosure report |
| `snapshot` | hourly during a vote | A **hash** of the internal live snapshot; the snapshot itself is published after close |
| `query` | per enclave query | What was asked of the live data and when (never the answer) |
| `audit` | periodically | Eligibility checks: member counts, billing reconciliation, sampling |
| `appBuild` | per app release | The hash of a released app build |
| `anchor` | per anchor | Proof that a checkpoint was fixed in a public chain |

## 5. Schemes (version 1 registry)

| Port | Scheme id | Meaning |
|---|---|---|
| admission | `devote-issued-v1` | Devote's admission key signs each admission after identity verification |
| membership | `semaphore-v4` | Semaphore v4 groups (one per franchise); Groth16 proofs; nullifier per scope |
| encryption | `hpke-xwing-v1` | HPKE with the X-Wing hybrid KEM (X25519 + ML-KEM-768), HKDF-SHA256, AES-256-GCM |
| transport | `ohttp-v1` | Oblivious HTTP relay with random send delays (not checkable from the record; stated for transparency) |
| tally | `reveal-and-count-v1` | Section 9 |
| disclosure | `sdc-kl-v1` | Section 10 |
| slice | `confidential-space-dp-v1` | Live slices from an attested Google Confidential Space workload, minimum group size plus differential-privacy noise |
| anchor | `ots-bitcoin-v1`, `ethereum-l1-v1` | Section 7 |
| dataStore | `arweave-v1`, `gcs-mirror-v1`, `zenodo-v1` | Where entries and bundles are also kept |

A new approach is a new scheme id. Entries under older ids stay verifiable by the rules for those ids.

## 6. Ballots, rows and commitments

A voter's phone sends three kinds of **row** for one vote. Each is a separate `ballot` entry with its
own nullifier scope, so rows can't be linked to each other.

| rowType | Fields (committed) | Nullifier scope | Revealed at close |
|---|---|---|---|
| `main` | `choice`, `carry`, `area` | `bill:<billKey>` | yes, at disclosure-controlled levels |
| `demographic` | `choice`, `carry`, `value` (of `dimension`, stated in clear) | `bill:<billKey>/dim:<dimension>` | yes, at disclosure-controlled levels |
| `full` | none (contents only in the ciphertext) | `bill:<billKey>/full` | never |

### Fields and levels

Each field has a **ladder** of levels, given in the manifest. For example, `area`:
`constituency` → `region` → `nation`. Single-level fields (`choice`, `carry`) use the level `value`.

### Commitments

For every field, and every level of that field's ladder, the phone draws a fresh 32-byte random salt and
computes:

```
commitment = hex( SHA-256( "devote-record/commit/v1" || 0x00 || JCS([field, level, value]) || salt ) )
```

- `value` is the field's value at that level: the constituency code at `constituency`, its region at
  `region`, and so on.
- `carry` values are JSON booleans; all others are strings.

### The message bound by the proof

```
message = hex( SHA-256( JCS({ "commitments": <commitments object>, "ciphertext": SHA-256(ciphertext.ct bytes) as hex }) ) )
```

The Semaphore proof's `message` is this value, read as a big-endian integer and reduced as Semaphore v4
reduces messages. A ballot whose proof doesn't bind its commitments and ciphertext is invalid.

### Validity

A `ballot` entry is valid when:
- its manifest exists earlier in the log, and the ballot comes before the stage's first `reveal` entry
  (the service stops accepting at `closesAt` plus `graceSeconds`; anything appended after the first
  reveal is invalid);
- its `groupRoot` is the root frozen in that manifest for its `franchise`;
- the proof verifies for `groupRoot`, `nullifier`, `message` and `scope`;
- its `scope` matches its `rowType` and the manifest's `billKey`.

Ballots appended to the log by the phone's own fallback (published to a data store, then imported)
follow the same rules.

### Supersession

Within one stage, the last valid ballot for a given (`scope`, `nullifier`), in log order, is the voter's
ballot for that stage. Earlier ones are **superseded** and never revealed.

### Carry

For stage S of a bill, a voter's counted row is:
- their last row cast during S; otherwise
- their last revealed row from an earlier stage of the same bill whose `carry` revealed as `true`, among
  stages listed in S's manifest `carryFrom`.

## 7. Anchors

- **`ots-bitcoin-v1`:** an OpenTimestamps proof (base64url) committing to `SHA-256(checkpoint note
  text)`. It verifies with Bitcoin block headers alone.
- **`ethereum-l1-v1`:** an Ethereum mainnet transaction whose input data is `0x` followed by
  `SHA-256(checkpoint note text)`. The anchor gives chain id, transaction hash and block number.

## 8. Disclosure and reveal

At close, the enclave chooses for every counted row the level at which each field is published. It may
**withhold** a field entirely. A `reveal` entry then gives, per counted ballot and field, either:
- `{ "level": ..., "value": ..., "salt": ... }`, or
- `{ "withheld": true }`.

A verifier recomputes the commitment from the revealed `[field, level, value]` and salt. It MUST find the
result among the ballot's committed values for that field and level.

## 9. Tally (`reveal-and-count-v1`)

`tally.totals` is the count of counted main rows by revealed `choice`. Every table in `tally.tables` is
recomputable from revealed rows:
- **area tables** from main rows;
- **dimension tables** from demographic rows of that dimension.

A row whose field is withheld counts in the totals but not in that field's table.

## 10. Disclosure rules (`sdc-kl-v1`)

The manifest states `k` and `l`. For each row type, published rows are grouped by their revealed
(field, level, value) quasi-identifiers. Withheld fields are excluded from the grouping, and so are
`choice` and `carry`. Those two are the voter's preferences, not attributes that could identify them.
`carry` can't be hidden in any verifiable design: which rows carried is visible from the next stage's
count.
Every group MUST have:
- at least `k` rows;
- at least `l` distinct `choice` values.

The tally's `disclosureReport` states how many fields were generalised and withheld. Verifiers check the
rules on what was published. They can't see what was withheld, by design.

## 11. Eligibility (`devote-issued-v1`)

- Admissions are signed with Devote's admission key (Ed25519). Its public key is published in the
  `manifest` and on the site.
- The signature covers `"devote-record/admission/v1" || 0x00 || JCS(body without signatures)`, and the
  same with `revocation` for revocations.
- A group's members are the admitted commitments for that franchise, in log order, minus those revoked
  before the manifest.
- The manifest's `groupRoots` MUST equal the Semaphore root of that list.
- Under this scheme Devote vouches for eligibility. `audit` entries give the checks a reader can use;
  later schemes move the signature to independent parties.

## 12. Versioning

Changing anything in this document that alters what a valid entry is requires a new envelope `v` or a
new scheme id. Clarifications don't.
