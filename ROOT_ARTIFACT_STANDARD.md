# Root Artifact Standard — The Alternative to Seed Phrases and Private Keys

**Status:** design draft — the proposed replacement for BIP-39 mnemonic phrases
and bare private keys as *root key material*.
**Relation to this repo:** this is the general standard; `ENVELOPE_SPEC.md` is
its instance inside Guardian Protocol. Guardian Protocol becomes the custody
and recovery infrastructure of this standard (born-distributed mode), not a
vault for legacy words.
**Not implemented.** Protocol documents remain authoritative; this file defines
new material, it does not amend them.

---

## 1. Problem: the root, not the vault

A vault can shard any secret — but the secrets people actually protect are
BIP-39 phrases and bare private keys. Those roots are born vulnerable:

| Structural flaw of current roots | Consequence |
|---|---|
| Readable encoding (12/24 words, or a scalar) | Anyone who sees it owns the funds; social engineering target |
| Single material restores everything | One copy lost/steal = total loss/compromise |
| 4-bit checksum, no integrity material | Tampering and generation faults (ColdCard class) are undetectable |
| No versioning | Silent breakage, no PQ migration path without re-backup |
| No policy | Cannot express quorum, delay, heirs, rotation — all delegated to fragile human behavior |
| Recovery is a reveal | The moment of restore is a theft/coercion moment |

The alternative replaces the *root material itself*: a sealed, versioned,
policy-carrying, error-corrected, verifiable artifact that a wallet derives
keys from — never a phrase, never a bare key.

## 2. The Root Artifact

```text
Artifact = shell ‖ sealed_root

shell (non-confidential):
  format_id          = "gp/root-artifact/v1"
  version            = 1
  crypto_suite       = { kdf: argon2id-256MiB, aead: xchacha20poly1305,
                         ecc: { n, t, c } }
  policy_block       = { policy_hash, quorum, delay, rotation_pointer,
                         heir_hints }
  verification       = { artifact_digest, generation_nonce, fragment_commits[] }
  seal               = AEAD tag over (canonical(shell) ‖ core_ciphertext)

sealed_root (encrypted under K_wrap):
  root_entropy       = 128 or 256 bits   # the only secret; words never exist
  derivation_ctx     = {"bip32-root-v1"} # deterministic, versioned derivation
  rotation_key       = optional per-artifact rotation secret
```

The root entropy is the same 128/256 bits any scheme needs — entropy is not
the vulnerability; encoding, single-materiality, and lack of policy are.

## 3. Why derivation stays ecosystem-compatible

Keys are derived from the opened root with the existing, unchanged derivation
(BIP-32 style):

```text
opened root  →  BIP-32 master key  →  derived keys  →  unchanged addresses
```

Because the artifact replaces only the root *encoding and custody*, addresses
and signatures do not change. A wallet can support both BIP-39 and the Root
Artifact without forking anything — the adoption question becomes "which root
format do I create at setup", not "which ecosystem do I join".

## 4. Wallet flows

**Create:** generate entropy → seal into artifact (Argon2id + AEAD) → present
QR/UR + verification digest. Words are never displayed, printed, or spoken.

**Back up:** the artifact, not words. Metal/paper/QR/phone copy. Partial damage
correctable via ECC (n ≥ t+2c, confirm-then-correct — never silent auto-fix).

**Verify (periodic):** re-derive `artifact_digest` on any device. Mismatch ⇒
tampering or generation fault — the check that would have caught the ColdCard
entropy failure. This property does not exist in any current root format.

**Restore:** scan + passphrase → seal and ECC verified → root opened on device
only → derivation → same keys. Recovery is a verify-then-open process, not a
reveal of words.

**Migrate (PQ, later suites):** write the same root into a newer
`crypto_suite`; old artifacts remain readable. No re-backup of new material —
only a re-seal of the same root.

## 5. Born-distributed mode (no single material)

The strongest form: the sealed core is threshold-sharded at birth through
Guardian Protocol (k-of-n custody + s-of-m authorization + Begin→Delay→Release
+ owner hard cancel). Then:

- no single material restores the root,
- recovery is a governed process (delay, cancel, rotation), not a reveal,
- the vault is no longer a vault *around* legacy words — the root is born
  inside the infrastructure,
- `ENVELOPE_SPEC.md` defines the owner-side artifact of this mode.

## 6. Honest limits

- Any scheme requires the underlying entropy; "no seed" is impossible. The
  claim is a root without the *six structural flaws*, not without randomness.
- A sealed artifact can be opened under duress; coercion resistance lives in
  the protocol layer (delay + cancel + decoy distribution), not in the format.
- A malicious generating device can lie in its own transcript (dishonest
  prover); verification detects faults and tamper, not fully malicious
  generation.
- The passphrase becomes a single point; born-distributed mode removes it.

## 7. Adoption reality (from the research, not optimism)

Successors to BIP-39 (SLIP-39, codex32, Formosa) were each superior formats and
each failed adoption — a spec alone does not get adopted. The Root Artifact
addresses the known causes of that failure:

1. **Deployment-first**: it ships inside Guardian Protocol (a working system)
   before it is proposed anywhere else.
2. **No ecosystem fork**: identical derived keys mean zero migration cost at
   the address layer.
3. **One concrete unclaimed property**: the verification digest — the only
   root format that can prove its own integrity/taint.
4. **The PQ window**: BIP-361 Phase C (ZK seed possession) was removed
   (Apr 17, 2026) — the root-as-witness slot is open, and this standard fills
   the XMSS/stateful-backup gap no one else is working.

Honest ceiling: broad wallet adoption is a long shot; the defensible goal is
the artifact as research proof + Guardian as its deployment, with the standard
documented so anyone can build on it.

## 8. Open items before implementation

1. Canonical serialization (shell/core) with length-prefixed domain separation.
2. Argon2id parameters (m=256MiB, t=3) final review.
3. ECC defaults for physical artifact sizes (QR budget vs fragments).
4. Derivation-context registry: `derivation_ctx` namespacing to prevent
   cross-suite root reuse.
5. Whether born-distributed mode requires protocol changes (guardians already
   hold shards; the new part is "entropy born into the artifact, then sharded"
   instead of "secret pasted in").
