# record-verifier: notes for agents

- This repo is the **single definition** of the vote ledger's format. SPEC.md and schemas/ are
  normative. Devote's services (vote_ledger, vote_enclave, models_core) implement from them; never
  define ledger fields anywhere else.
- It will be **public** (Apache-2.0). Never put anything private in it: no Devote internals, paths,
  keys, URLs of private services, or user data.
- Keep it dependency-light and browser-safe: WebCrypto only, no Buffer, no Node-only APIs in src/.
- A change that alters what a valid entry is needs a new envelope `v` or a new scheme id (SPEC.md section 12).
- `npm run check` before committing.
