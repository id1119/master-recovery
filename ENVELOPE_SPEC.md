# Envelope Spec — The Owner's Master Backup Artifact (DESIGN DRAFT v2)

**Status:** design draft — NOT implemented, outside the hackathon scope.
**Relation to protocol:** extension, not redesign. The envelope changes no
protocol flow; it defines the format of the artifact the owner stores offline
and uses to re-initialize a fresh device and to cancel. All objects referenced
below already exist in `PROTOCOL.md`; this document only formats their owner-side
copies into one versioned, sealed, error-corrected, verifiable artifact.

If any field below contradicts a protocol document, the protocol document wins
(source-of-truth order) and this spec must be fixed, not the protocol.

---

## 1. Purpose and Threat Model

The owner currently holds: the non-confidential Recovery Card, the private
per-config cancellation key (`owner-control`), and knowledge of capsule
locators. If the owner loses the device, all of it is gone: no cancel authority
(`SECURITY.md` §4), no bootstrap path. The envelope is the owner's offline
master backup of exactly this material.

Threats it must survive, and the countermeasure for each:

| Threat | Countermeasure |
|---|---|
| Theft of the artifact | Sealed core (AEAD under Argon2id-derived key); shell has no key material |
| Damage / partial loss | Reed-Solomon over the encoded artifact, n ≥ t+2c, confirm-then-correct |
| Tampering / silent corruption | AEAD seal with shell as AAD + per-fragment commitments |
| Buggy/bad generation (ColdCard class) | Verification material (§6): re-derive the digest on a fresh device |
| Future quantum attacker | 256-bit symmetric wrap (Grover-safe); optional hybrid KEM suite (§5) |
| Format evolution | `format_id ‖ version ‖ crypto_suite`; forward-rejecting parse |
| Forced disclosure | Distributional decoys — optional extension, §9 (protocol layer still primary) |

Explicit non-claims (mirroring `SECURITY.md` §7): the envelope is not a secret
container for DEK or A — the owner never holds either (protocol separation,
`SECURITY.md` §1). It does not make the cancellation key compromise-resistant
beyond the underlying key. It does not protect against a malicious device
during generation (dishonest-prover limit, see §6).

## 2. Artifact Layout

```text
Envelope = shell ‖ seal

shell (non-confidential, readable without the passphrase):
  format_id          = "gp/envelope/v2"
  version            = 2
  crypto_suite       = { kdf: argon2id-256MiB, aead: xchacha20poly1305,
                         rs: { n, t, c } }
  config_id
  config_version
  policy_block       = { signer_set_commitment, owner_cancel_pubkey,
                         s_of_m, k_of_n, delay,
                         policy_hash, rotation_pointer, tombstone_pointer }
  recovery_card      = Recovery Card contents (capsule locators, relay bases,
                         opaque signer mailboxes) + capsule replicas
  verification       = { envelope_digest, generation_nonce,
                         fragment_commits[] }
  seal               = AEAD tag over (canonical(shell) ‖ core_ciphertext)

core (sealed, encrypted under K_wrap):
  owner_cancel_private_key
  recovery_descriptor_locator(s)      # capsule mirror hints, not the roster
  required_recovery_metadata          # as defined in PROTOCOL.md §2.9
```

The guardian roster never appears in the envelope — only locator hints for
capsules the owner already knew. `owner_cancel_private_key` is the only secret
core field; everything else in core is bootstrap material.

## 3. Sealing (K_wrap)

```text
salt     = random 16 bytes, stored in shell
K_wrap   = Argon2id(password = owner_passphrase, salt, m=256MiB, t=3, p=1)
core_iv  = random 24 bytes, stored in shell
seal     = XChaCha20Poly1305_Encrypt(K_wrap, core_iv,
           canonical(shell) ‖ core_ciphertext)     # shell is AAD
```

- Argon2id 256 MiB (not PBKDF2) per the crypto review; parameterized in
  `crypto_suite` so cost is negotiable.
- The AEAD tag covers the canonical shell, so any shell tampering fails the
  seal — no standalone MAC (review correction).
- 256-bit symmetric wrap is Grover-safe; the practical bound is passphrase
  entropy, stated in the UI: recommend a passphrase of ≥128 bits of entropy or
  passphrase + a hardware-pinned pairing secret.

## 4. Error Correction

```text
encoded  = canonical(shell ‖ core_ciphertext)
F_1..F_n = Reed-Solomon(n, t) over encoded        # any t of n reconstruct
commit_i = SHA256("gp/envelope/frag/v2" ‖ config_id ‖ version ‖ i ‖ F_i)
```

- Choose n ≥ t + 2c where c = number of correctable fragment losses/errors
  (review correction: t+2c, not t+2c+1).
- **Confirm-then-correct, never silent auto-correct:** on open, verify the
  AEAD seal first. If it fails, do NOT auto-apply RS correction; surface the
  fragment commit mismatch to the owner and apply correction only on explicit
  confirmation. Rationale: silent correction masks active tampering the same
  way silent decoy failure did in VeraCrypt CVE-2026-54073.
- Fragment commits go in `verification`, so partial damage is located
  per-fragment without opening the artifact.

## 5. Crypto Suite Selection

`crypto_suite` names the whole stack; clients parse by `format_id ‖ version ‖
crypto_suite` and forward-reject anything newer than they implement.

- `v2-default`: symmetric-only wrap (§3) — offline artifact, no transport
  adversary; quantum brute force of a 256-bit AEAD key is not a realistic
  attack, and no custom combiner is introduced (AGENTS.md cryptography rules).
- `v2-hybrid` (optional): wrap key = symmetric K_wrap XOR-decapsulated X-Wing
  (X25519 + ML-KEM-768) to an owner KEM holder key stored outside the
  envelope. Added only so the envelope can ride an owner hardware token later;
  the X-Wing profile is used only through the maintained RustCrypto crate, per
  AGENTS.md. Default is `v2-default`.

## 6. Verification Material (the novel claim)

Purpose: the owner can check, anytime and on any device, that the artifact is
exactly what was generated — the open void the research identified (nothing
prior puts verification material into a single-device backup).

```text
envelope_digest = SHA256("gp/envelope/digest/v2" ‖ config_id ‖ version
                         ‖ generation_nonce ‖ canonical(shell) ‖ core_ciphertext)
```

- `envelope_digest` + `generation_nonce` are stored in shell and re-derived
  from the artifact bytes. Re-derivation mismatch ⇒ the artifact is not what
  was generated: tampered, damaged beyond RS, or produced by a faulty
  generator (ColdCard-class entropy failure) — the check that caught the
  Jul 30, 2026 incident would exist here.
- Commit-reveal: the owner may destroy the nonce and re-reveal it from the
  envelope; generation-time commitment binding follows the Trezor PR #4155
  pattern but at artifact level (generation-time AND post-hoc checks).
- Dishonest-prover limit: a malicious generating device can lie in its own
  transcript; verification detects honest-fault/tamper, not a fully malicious
  generator. State this in any paper claim.

## 7. Policy Redundancy and the Format↔Protocol Seam

- `policy_block` lives plaintext in shell (it is not secret — guardians
  already see `policy_record`) and is pinned by `policy_hash`. On partial
  artifact damage, the policy is additionally recoverable from any t-1
  fragments plus one fragment-derived commitment — never fully lost.
- `rotation_pointer` = hash of the successor config capsule's commitment;
  rotation binds the envelope to the protocol's rotate-on-recovery
  (`PROTOCOL.md` §4) without re-backing-up.
- `tombstone_pointer` = external pointer to the public cancellation log entry
  (hash-chain), so a fresh device can learn "this config was cancelled" before
  attempting recovery. External pointers keep the artifact small and let the
  protocol evolve the log format without envelope version bumps.
- Missing by design (open items for v3): validity windows, suspension state,
  canonical serialization choice — flagged, not solved, to keep v2 scoped.

## 8. Owner Workflows

**Create (fresh device or setup):** generate envelope from owner-control +
Recovery Card → print/engrave/QR via the existing encoding pipeline (wordlist
is a display detail; UR/QR preferred). Verify: re-derive digest once before
storing.

**Re-init (device lost):** open envelope with passphrase → verify seal + RS +
digest → restore owner-control, Recovery Card, and capsule locators → proceed
with normal recovery (`PROTOCOL.md` §3).

**Check (periodic):** re-derive digest on a fresh device; mismatch ⇒ damage or
taint, escalate per §4/§6. This is the feature nothing else ships.

**Cancel from the artifact:** owner-control restored from envelope is the only
cancel authority — unchanged protocol semantics (`PROTOCOL.md` §3.8).

## 9. Coercion (optional extension, v3+)

Decoy envelope: a valid-format envelope whose core is sealed over decoy key
material and whose shell carries a decoy `generation_nonce`/digest pair.
Security claim must be **distributional indistinguishability** over many
envelopes (the PI game as stated is broken — review correction), not
per-transcript indistinguishability. The protocol layer (delay + hard cancel,
`SECURITY.md` §3–4) remains the primary coercion defense; the envelope only
preserves ambiguity. Not in v2 scope.

## 10. What This Spec Deliberately Does Not Do

- No new custom primitives, no combiner invention (AGENTS.md).
- No roster material, no DEK/A in the artifact (protocol separation).
- No blockchain, no production mixnet, no machine-checked proofs.
- No silent auto-correction, no decoy-by-default.
- Does not alter any `PROTOCOL.md` flow; guardians/signers/relays never see
  the envelope.

## 11. Open Items Before Implementation

1. Canonical serialization format for shell/core (bincode? JSON? CBOR?) —
   must be stable and length-prefixed for domain separation.
2. Argon2id parameter review (m=256MiB, t=3) against memory-hardness guidance.
3. `n, t, c` defaults for a printed/engraved artifact (physical size budget).
4. Whether `v2-hybrid` enters v2 or waits for v3 with the decoy extension.
