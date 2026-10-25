# The Devote Public Record: format and verification, version 1

Status: **draft 2**, 2026-10-25. Draft 2 settles the gaps found while building the phone package, the
enclave and the ledger service (see the changelog at the end). This document is the single definition of the record's format.
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

How the values are passed to Semaphore v4 (`generateProof` and `verifyProof`):
- **message:** the 32 bytes of `message` as a big-endian unsigned integer.
- **scope:** the big-endian unsigned integer of `SHA-256(UTF-8(scope string))`, for example
  `SHA-256("bill:<billKey>")`. The scope string itself is too long for Semaphore's 31-byte string form.
- Semaphore then hashes both, as v4 always does. The proof's public `nullifier` and `merkleTreeRoot`
  MUST equal the ballot's `nullifier` and `groupRoot`.

A ballot whose proof doesn't bind its commitments and ciphertext is invalid.

The message binds `ct` but not `enc`. Changing `enc` can only make a row undecryptable, never change
what it says. The voter's phone checks that its exact entry is in the log (section 8), so a changed
`enc` is caught there.

### Proofs and groups

- A ballot's `proof.merkleTreeDepth` MUST equal the `depth` frozen for its franchise in the manifest.
  Every proof in a stage then has the same shape, and the depth says nothing about the voter.
- Phones MUST build their own Merkle path from public data (section 11). They MUST never ask a server for
  "my" path, which would reveal which commitment is theirs. Two ways count as building from public data:
  - from the whole list of admissions; or
  - for large groups, from the voter's own **block** of admissions plus the published **block roots**.
    Blocks are aligned runs of `blockSize` leaves (a power of two, 65,536 by default) in admission
    order, each a complete subtree of the group's tree (the last may be partial). The manifest records
    `blockSize` and `blockRootsSha256` for each franchise. The block-roots file, a JSON array of the
    roots in order as decimal strings, is published next to the log at
    `groups/<manifest leaf index>/<franchise>.json`, in canonical form (JCS, e.g. `["123","456"]`).
    `blockRootsSha256` is the lowercase hex `SHA-256` of those canonical bytes.
    Anyone can recompute it from the admissions and check its hash, and the roots must combine to
    `groupRoots[franchise].root`. Fetching one block tells whoever serves it only which block of
    `blockSize` people a phone belongs to. Phones SHOULD fetch blocks through the relay, and the vote
    itself stays anonymous across the whole group.

### Encryption (`hpke-xwing-v1`)

Every row, including demographic and full rows, carries a ciphertext:
- **Algorithm:** HPKE base mode with the X-Wing KEM (X25519 + ML-KEM-768), HKDF-SHA256 and AES-256-GCM.
- **Recipient key:** the stage's encryption key (`manifest.encryption`).
- **`info`:** the bytes `devote-record/row/v1`.
- **`aad`:** `JCS({ "keyId": ..., "rowType": ..., "scope": ... })`, so a ciphertext only opens as the row
  it was made for.
- **Plaintext:** canonical JSON, zero-padded to a multiple of 512 bytes. JSON never contains a NUL byte,
  so the padding is unambiguous.
  - **main and demographic rows:** `{ "v": 1, "rowType": ..., "dimension"?: ..., "fields": { <field>:
    { <level>: { "value": ..., "salt": <base64url> } } } }`. These are the openings of every commitment.
  - **full rows:** `{ "v": 1, "rowType": "full", "fields": { "choice": ..., "carry": ..., "area": {
    <level>: <value> }, "demographics": { <dimension>: { <level>: <value> } } } }`.

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

A carried row counts with the values revealed in its own stage, unless S's `reveal` entries
**re-reveal** it. A re-reveal names the earlier ballot's leaf index and opens its commitments at the
same level or a coarser one; `choice` and `carry` can't change. Disclosure control uses this to hide
small changes between stages (section 10).

## 7. Anchors

The anchored value is `SHA-256` of the checkpoint's **signed text**: the note body up to and including
its final newline, without the blank line and signature lines. Adding a witness cosignature doesn't
change it. `anchor.checkpoint.noteSha256` is this value.

- **`ots-bitcoin-v1`:** an OpenTimestamps proof (base64url) committing to that value. It verifies with
  Bitcoin block headers alone.
- **`ethereum-l1-v1`:** an Ethereum mainnet transaction whose input data is `0x` followed by that value.
  The anchor gives chain id, transaction hash and block number.

## 8. Disclosure and reveal

At close, the enclave chooses for every counted row the level at which each field is published. It may
**withhold** a field entirely. A `reveal` entry then gives, per counted ballot and field, either:
- `{ "level": ..., "value": ..., "salt": ... }`, or
- `{ "withheld": true }`.

A verifier recomputes the commitment from the revealed `[field, level, value]` and salt. It MUST find the
result among the ballot's committed values for that field and level.

A counted ballot whose ciphertext doesn't decrypt, or whose plaintext doesn't open its own commitments,
is revealed as `{ "ballot": <index>, "undecryptable": true }`. It counts nowhere. The tally states how
many there were (`disclosureReport.undecryptable`), so a high number is visible to everyone.

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
- at least `l` distinct `choice` values;
- at least `minChoiceSupport` rows (default 1) behind every choice that appears in it. A value of 2 stops
  a lone dissenter in a group from learning that everyone else voted the other way.

**Exemption:** a group that contains every published row of its row type (and dimension) is exempt from
the `l` and `minChoiceSupport` rules. It is the stage's total, which is public anyway. Without this, a
unanimous stage could never be published.

The groups checked are all rows **counted** in the stage, its own and carried ones, with the values they
are counted at.

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

## 12. Live statistics (`confidential-space-dp-v1`)

During a vote the enclave answers slice queries and makes hourly snapshots. Both use exact
discrete-Gaussian noise under zero-concentrated differential privacy (zCDP). The manifest's optional
`slice` object states the parameters:

```json
{ "mechanism": "discrete-gaussian-zcdp", "rhoPerStage": 2, "rhoPerQuery": 0.02, "snapshotShare": 0.5 }
```

- The budget a stage has spent is counted from its public `query` and `snapshot` entries, so it can't be
  reset by restarting anything.
- A question is logged before it is answered, and nothing is answered if logging fails.
- A **snapshot** is `JCS({ "manifest": <index>, "asOf": <ISO hour>, "sigma": <number>, "tables":
  [<countTable with noisy counts>] })`. The `snapshot` entry holds its SHA-256. The tally lists where each
  snapshot is published after close (`tally.snapshots`), and anyone can check the hash.

## 13. Versioning

Changing anything in this document that alters what a valid entry is requires a new envelope `v` or a
new scheme id. Clarifications don't.

## Appendix A. Canonical ladders (Great Britain, version 1)

Phones, the enclave and published tables use these names and values.

| Field or dimension | Levels, finest first | Values |
|---|---|---|
| `area` | `constituency`, `region`, `nation` | ONS GSS codes for the franchise's constituency set; `region` is the ONS region (E12…) in England and the nation code in Scotland, Wales and Northern Ireland; `nation` is E92000001, W92000004, S92000003 or N92000002 |
| `age` | `5y`, `10y`, `20y` | `5y`: `16-19`, `20-24`, `25-29`, …, `80-84`, `85+`. `10y`: `16-19`, `20-29`, `30-39`, …, `70-79`, `80+`. `20y`: `16-39`, `40-59`, `60-79`, `80+` |
| `sex` | `value` | `female`, `male`, `other` (as on the identity document) |
| `ethnicity` | `detailed`, `broad` | `detailed`: the 19 ONS 2021 categories as lowercase slugs; `broad`: `asian`, `black`, `mixed`, `white`, `other` |

Self-declared dimensions (ethnicity and others) are sent only with the voter's explicit consent.

## Changelog

- **Draft 2 (2026-10-25):**
  - HPKE `info`, `aad` and plaintext format are fixed, with 512-byte padding.
  - Proof depth is fixed per franchise, and phones build their Merkle path locally, from the whole list or
    from their own block plus published block roots.
  - Carried rows can be re-revealed at a coarser level.
  - Anchors hash the signed text without signatures.
  - Undecryptable ballots are marked as such.
  - New disclosure rules: `minChoiceSupport`, an exemption for whole-stage groups, and checking over
    counted rows.
  - Live statistics and snapshot format are defined.
  - Canonical ladders for Great Britain (Appendix A).
- **Draft 1 (2026-10-25):** first version.
