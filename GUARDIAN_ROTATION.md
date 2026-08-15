# Guardian Rotation for Master Recovery

Status: authoritative protocol-v3 Guardian Rotation specification.

Date: 2026-08-15

This document follows the requested eight-phase analysis. On 2026-08-14 the
owner explicitly authorized this document as the protocol-v3 Guardian Rotation
specification and selected Zcash Foundation FROST RTS plus DKG share refresh.
`MASTER_PROMPT.md` incorporates that decision. Protocol v2 remains immutable
and recovery-only; rotation requires an explicit migration to v3.

## Executive decision

The strongest long-term design is **Staged Verifiable Guardian Epochs**:

1. every recovery and rotation is bound to one immutable guardian epoch;
2. a signer threshold authorizes an exact proposed successor epoch through a
   Begin -> Delay -> Release -> Activate flow;
3. the setup-time owner cancellation key can permanently veto the exact
   rotation before activation;
4. a reviewed dynamic proactive secret-sharing (DPSS) protocol transfers and
   refreshes the DEK sharing from the old committee to the new committee
   without reconstructing DEK at one participant;
5. ciphertext fragments are repaired from threshold-valid encrypted
   ciphertext fragments without decrypting the payload;
6. every new guardian is durably provisioned before an activation certificate
   can be committed;
7. a small Byzantine quorum of non-enumerable config witnesses makes one
   successor epoch atomic and lets a fresh client reject rollback;
8. old epochs drain already-pending recoveries and are then securely erased.

This is not implementable by merely extending the current `blahaj` wrapper.
The current guardians never possess plaintext DEK shares: they store
`E_i = AEAD(HKDF(A, ...), D_i)`. A DPSS handoff therefore needs a
signer-authorized, per-guardian unwrap grant so each old guardian can operate
on its own `D_i` in zeroizing memory. It also needs a complete reviewed DPSS
implementation, not locally written finite-field or resharing code.

The selected implementation is `frost-ristretto255` 3.x from the Zcash
Foundation FROST project. A replacement first receives one freshly issued
share through the library's Repairable Threshold Scheme (RTS, based on ePrint
2017/1155). The exact successor roster then runs the library's DKG share-refresh
protocol, whose zero-constant polynomials retain the Ristretto255 scalar DEK
while independently refreshing every successor share and excluding the retired
guardian. All participants must agree on the complete round transcript; the
application does not use the library as a partial-quorum consensus protocol.

The library is maintained and the FROST codebase has a historical NCC audit,
but DKG refresh was added after that audit. The exact RTS + DKG-refresh
integration therefore requires professional cryptographic review before a
production deployment. This prototype uses only the library APIs: it does not
implement field arithmetic, Shamir interpolation, VSS commitments, repair
equations, or the FROST combiner locally.

Therefore:

- **Implemented target:** Staged Verifiable Guardian Epochs with
  `frost-ristretto255` RTS + full-roster DKG refresh.
- **Safe interim/fallback:** an owner-controlled, recovery-equivalent epoch
  rebuild using the current primitives. It can avoid reconstructing the
  plaintext, but it reconstructs A and DEK in one client and is not proactive
  distributed resharing.
- **Implementation gate satisfied for the prototype:** the construction and
  maintained compiling provider are named above. Do not copy equations from a
  paper into `gp-crypto`. Production enablement remains gated on an external
  review of this integration.

## Implemented prototype evidence

The repository now contains both deterministic and live-network executions of
this design:

- `gp-core::RotationMachine` is serialized inside each live guardian session
  and is also used by `gp-sim`; no separate network activation shortcut exists;
- `gp-network setup-v3`, `rotate-v3`, `discover-v3`, and `recover-v3` execute
  the complete actor flow through TCP/HTTP relay mailboxes;
- ZF FROST RTS provider messages and refresh-DKG direct messages are signed,
  sequence checked, and X-Wing sealed to the exact peer; coordinator-visible
  objects contain ciphertext fragments but no DEK share or payload plaintext;
- every successor record is staged, Merkle-committed, and durably PREPARED
  before signer Activate votes and the witness QC. The record and its encrypted
  DEK share remain local to that guardian: the coordinator receives only the
  prepared-record leaf and returns the resulting Merkle root/path;
- abort requires a signer threshold rather than one signer's signature;
- `cancel-rotation-v3` first persists a `2f+1` witness veto against the exact
  rotation, then persists owner-authorized tombstones at enough old guardians
  to break the handoff quorum. Signers release predecessor plan locks only
  after validating that owner certificate plus the witness-veto proof; a
  non-owner cleanup instead requires a signer-threshold Abort certificate;
- old fragment contributions carry their complete committed record leaf, so
  the coordinator verifies the predecessor material-root proof before using a
  ciphertext fragment;
- the setup capsule also commits to the deterministic raw Reed-Solomon
  fragment set. Every successor verifies its exact fragment and index against
  that stable payload-generation root before signing a preparation receipt;
- activation derives its draining-request set locally at each guardian. New
  old-epoch Begin requests are rejected while exact pre-activation requests
  remain drainable;
- `tools/test-v3-network.sh` proves live setup and recovery, shuts down the
  guardian being replaced and one of four witnesses, owner-cancels and retries
  an in-flight rotation, completes two consecutive replacements using the
  remaining `2f+1` witnesses, discovers epoch 3 with the unchanged Recovery
  Card, and performs byte-identical recovery. The coordinator result records
  zero payload decryptions.

This evidence completes the hackathon-prototype path, not the production gate.
The exact RTS + refresh integration still lacks the external cryptographic
review required by section 8.5. The ephemeral CLI also preserves safe actor
state but is not yet a replicated, automatically resumed coordinator job after
an arbitrary coordinator-process crash.

---

# PHASE 1 — Existing protocol analysis

## 1.1 Protocol-v2 baseline cryptographic state

The code matches the documented A/DEK design:

```text
A   -- Shamir s-of-m --> signer A shares

secret -- XChaCha20-Poly1305(DEK, payload_context(config_version)) --> C
C      -- Reed-Solomon k-of-n --> F_i
DEK    -- Shamir k-of-n --> D_i
D_i    -- XChaCha20-Poly1305(HKDF(A, config/version/index)) --> E_i

guardian i stores F_i + E_i + Merkle proof + policy
```

The v2 implementation facts that motivated the v3 amendment are:

- `gp-network::protocol::create_setup` creates A, DEK, signer shares, DEK
  shares, wrapped shares, fragments, commitments, the descriptor, and the
  capsule in one ephemeral setup client.
- `GuardianRecord` contains `ciphertext_fragment` and
  `encrypted_dek_share`; it does not contain `D_i`.
- only a recovery client reconstructs A, opens the descriptor, obtains at
  least k committed guardian records, decrypts `E_i`, reconstructs DEK and C,
  and finally decrypts the payload.
- guardian state is keyed by one opaque mailbox/slot and one
  `GuardianPolicy` with exactly one `config_version`.
- `GuardianMachine` rejects any request not equal to its one current version.
- the v2 simulator's “rotation” is a complete new setup after plaintext recovery.
  It creates fresh A, DEK, shares, ciphertext and slots from the recovered
  plaintext. It is not guardian repair or proactive refresh.
- the v2 network config store is deliberately write-once. It rejects a second
  capsule for a config id because no signed rotation message exists.
- a Recovery Card pins config id, signer commitment, owner cancellation key,
  signer mailboxes and store locators, but not a minimum/current config
  version or a quorum of authenticated config-store identities.

## 1.2 What the protocol-v2 baseline could and could not rotate

### Planned byte-for-byte handoff

An old guardian can send its exact `F_i` and `E_i` to a new operator without A,
DEK, or plaintext. This preserves the logical share index. It is only a copy:
the old guardian may retain the same material, the new guardian cannot prove
deletion, and no share is refreshed. It is unsuitable as the long-term
security mechanism.

### Repairing a lost ciphertext fragment

Any k valid `F_i` values reconstruct encrypted ciphertext C. C can be
Reed-Solomon encoded again without DEK and without plaintext. This operation
does reveal the ciphertext to the repair coordinator, but ciphertext is not
the plaintext security boundary.

### Repairing or refreshing a lost DEK share

The current architecture has two possible paths:

1. a client reconstructs A, obtains k `E_i`, decrypts k `D_i`, and acts as a
   new Shamir dealer; or
2. each old guardian receives its own A-derived unwrap key and participates in
   a reviewed distributed share-redistribution protocol.

Path 1 gives one client a recovery threshold and therefore the ability to
recover the secret, even if its software promises not to call payload decrypt.
Path 2 is not supported by `blahaj` or by the existing message/state model.

### Changing DEK without plaintext

It is not possible with the current AEAD layout. Replacing DEK requires
decrypting C and encrypting the plaintext under the new DEK. Re-sharing the
same DEK can refresh custody shares without plaintext, but cannot revoke a DEK
or an old threshold that was already learned.

## 1.3 Why a separate guardian epoch is necessary

Today `config_version` simultaneously binds:

- payload AEAD associated data;
- descriptor encryption;
- guardian-share wrapping;
- signer and guardian policy;
- recovery requests and replay state.

Incrementing it while retaining C makes payload authentication fail. Routine
guardian rotation must therefore separate:

```text
payload_generation   immutable for one encrypted payload/DEK
guardian_epoch       changes for guardian membership/share refresh
authorization_epoch  changes only when signer A sharing is separately refreshed
```

Every signed object can bind an `EpochRef` containing all three values. A full
configuration rotation advances all three and may change DEK. Routine guardian
rotation advances only `guardian_epoch` and retains payload generation and DEK.

## 1.4 Direct answers to the five architectural questions

1. A guardian can be replaced without plaintext by repairing C from fragments
   and refreshing the sharing of the existing DEK.
2. Avoiding DEK reconstruction requires distributed proactive resharing. A
   dealer-based fallback necessarily reconstructs DEK.
3. With the present A-wrapping, no: some signer-threshold-derived A authority
   must provide old/new per-guardian unwrap/wrap keys. A can remain confined to
   a rotation coordinator; it need not be sent to guardians.
4. The current architecture supports only recovery-equivalent dealer rotation,
   not safe non-custodial proactive rotation.
5. The smallest change for dealer rotation is guardian epochs plus signed
   two-phase activation and fresh-client rollback protection. The smallest
   change for no-single-party rotation is larger: add a vetted DPSS share
   format/protocol and transient per-guardian unwrap/wrap grants.

---

# PHASE 2 — Requirements and threat model

## 2.1 Required safety invariants

R1. No rotation operation exposes plaintext payload to signers, guardians,
relays, config witnesses, auditors, or the DPSS coordinator.

R2. In the production DPSS path, no single participant receives k DEK shares
or DEK.

R3. A rotation cannot proceed without the configured signer threshold
authorizing the exact predecessor, successor commitment, participants,
thresholds, session id, recipient keys, and deadlines.

R3a. The preliminary signer-authorized descriptor-open intent grants only A
shares to one exact rotation recipient. It cannot start guardian delay, release
custody material, select a successor or activate an epoch.

R4. Rotation is recovery-sensitive. Its release phase has at least the normal
recovery delay and the same owner reaction opportunity.

R5. The setup-time owner cancellation private key remains cancellation-only.
It may veto an exact rotation but cannot initiate or activate one.

R6. Guardians cannot autonomously change membership. Health evidence may
trigger a proposal; it never authorizes it.

R7. The old epoch remains ACTIVE until the complete new epoch is durably
PREPARED and an activation quorum certificate exists.

R8. A failed or abandoned preparation cannot reduce the active recovery
quorum.

R9. A recovery request is permanently bound to the epoch in which it began.
It never migrates to a successor epoch.

R10. Shares from different epochs are never accepted in one reconstruction.
Every share, proof, wrapping context and contribution binds its exact epoch and
actor index.

R11. Under the DPSS mobile-adversary bound, fewer than the corruption threshold
in every epoch learn nothing by accumulating shares from different epochs.

R12. A completed successor cannot be rolled back for a fresh client that can
reach the configured Byzantine read quorum.

R13. Two conflicting successors cannot both obtain activation quorum
certificates while the witness fault bound holds.

R14. The public/pseudonymous control plane never contains the plaintext
guardian roster, slot ids, operator identities, subshares, A, DEK, or C.

R15. An individual routine auditor learns only one session-scoped slot, not an
owner identity or full guardian set.

R16. Absence or timeout is not cryptographic proof of data loss and is not by
itself slashable.

R17. Honest nodes fail closed on a conflicting epoch, invalid certificate,
unknown predecessor, reboot ambiguity, incomplete DPSS transcript, missing
provisioning acknowledgement, or unavailable config-witness quorum.

R18. A participant that already learned DEK or plaintext cannot be made to
forget it by rotation.

## 2.2 Adversaries

The design considers:

- fewer than the signer authorization threshold compromised;
- a compromised signer threshold;
- fewer than the DPSS construction's old/new committee corruption bounds;
- an old or new guardian that withholds, equivocates, sends bad subshares,
  retains old state, or lies about provisioning;
- a mobile adversary that changes compromised guardians between epochs;
- Byzantine config witnesses within an explicit bound f;
- a malicious relay or global network observer;
- a malicious audit/watchtower process;
- a malicious rotation coordinator;
- partitions, crash/restart, delayed messages, reordering, duplication and
  replay.

The guardian recovery threshold k is not automatically the active Byzantine
resharing bound. For example, “5-of-8 can recover with three unavailable” does
not prove that an asynchronous malicious-party DPSS protocol can complete with
the same five. The DPSS suite must expose a separately reviewed:

```text
privacy_bound
active_fault_bound
minimum_old_handoff_quorum
minimum_new_committee_size
synchrony/model assumptions
```

The implementation must refuse a rotation whose live committee does not meet
those bounds. It must not silently reuse k as a Byzantine quorum.

## 2.3 Four different operations

The protocol must not call all changes “rotation”:

| Operation | Membership | DEK shares | DEK | Payload ciphertext |
|---|---|---|---|---|
| Guardian replacement | changes | must still be fully refreshed in the final design | unchanged | repaired/re-encoded |
| Proactive share refresh | same or changed | fresh independent epoch sharing | unchanged | unchanged or rewrapped |
| Cryptographic key rotation | may change | fresh | fresh | plaintext must be decrypted and re-encrypted |
| Full configuration rotation | signers, guardians and policies may change | fresh | normally fresh | re-encrypted under a new payload generation |

Routine replacement and periodic refresh use the same full DPSS handoff. The
protocol does not preserve an exact old share for an unchanged guardian,
because that would permit cross-epoch accumulation.

## 2.4 Secure deletion assumption

Proactive security requires honest parties to erase old shares, subshares,
unwrap keys, randomness and transcripts that contain secret material after a
successful epoch transition. This is a real assumption, not a remotely
provable fact.

If an old guardian intentionally keeps its old material, that material remains
valid for its old epoch. Fresh epoch shares cannot be mixed with it, but k
retained shares from the same old epoch still recover the old DEK sharing.
Classical software cannot prove deletion. Certified deletion would require a
different hardware or quantum assumption and is not part of this proposal.

---

# PHASE 3 — Candidate designs

## Candidate A — Logical-slot copy

The exiting guardian transfers the exact `F_i`, `E_i`, policy and slot role to
a new guardian. The descriptor changes only in routing information.

Benefits:

- no A, DEK, plaintext or new primitive;
- cheap and easy for a cooperative planned exit;
- current record format remains usable.

Fatal limitations:

- cannot repair a record that was already lost;
- the old guardian can retain an identical valid share;
- replacing different logical slots over time lets an attacker accumulate k
  distinct old shares from one unchanged sharing;
- it provides no proactive refresh and no cryptographic revocation;
- copying a share is not evidence that the replacement stored it durably.

Decision: reject as the long-term mechanism. It may be an emergency
availability copy only if explicitly labeled non-refreshing and followed by a
real epoch refresh.

## Candidate B — Recovery-equivalent dealer rebuild

A fresh, owner-controlled rotation client follows the existing recovery path,
reconstructs A and DEK, reconstructs encrypted C, creates a fresh Shamir
sharing of the same DEK, repairs/re-encodes fragments, and provisions a new
epoch. It never needs to decrypt C.

Benefits:

- uses only current maintained primitives;
- preserves the hidden roster because guardians do not coordinate;
- works when an old guardian has completely lost its record, provided at least
  k valid old records remain;
- supports threshold and committee-size changes;
- has moderate implementation and migration cost.

Limitations:

- the client obtains A, DEK and C and is cryptographically capable of
  decrypting plaintext;
- a malicious dealer can create an unrecoverable successor and no current
  guardian can verify share continuity independently;
- unattended rotation gives a service process recovery power;
- it is not distributed proactive resharing.

Decision: retain only as the explicit owner-assisted fallback and migration
path. Subject it to the full recovery delay and owner cancellation window.

## Candidate C — Verifiable dynamic proactive resharing

After signer authorization and delay, each old guardian receives only its own
A-derived unwrap grant, decrypts its own `D_i` in zeroizing memory, and runs a
reviewed active-adversary DPSS handoff to the new committee. New guardians
receive new independently randomized shares, verify them using the DPSS
construction, wrap them under new epoch-specific A-derived keys, and delete
plaintext shares.

The coordinator may reconstruct encrypted C from k fragments and create new
Reed-Solomon fragments. It holds A and C, but it never receives D shares or
DEK in the production path.

Benefits:

- no single participant reconstructs DEK;
- provides genuine mobile-adversary protection under per-epoch corruption and
  secure-erasure assumptions;
- repairs missing members and changes membership/thresholds;
- malicious subshares are detected by the selected construction;
- successor correctness is not based solely on trusting a new dealer.

Costs and incompatibilities:

- requires a full DPSS/VSS protocol and different share representation;
- requires private authenticated channels, reliable broadcast or an
  equivalent agreement layer, complaint handling and crash recovery;
- rotation participants necessarily learn session-scoped pseudonymous
  committee membership needed by the construction. This weakens the current
  “one guardian does not learn the full set” claim, although the roster remains
  absent from public state and operator identities/routes can remain hidden;
- reviewed constructions such as CHURP use assumptions and infrastructure
  (polynomial commitments, often public committee coordination) not present in
  this protocol;
- no directly suitable maintained Rust library was verified.

Decision: selected as the production target, with implementation blocked until
the authoritative specification accepts the limited metadata tradeoff and
names a vetted implementation.

## Candidate D — Wrapper key, proxy re-encryption, or extra custody secret

Introduce a stable custody key or proxy-re-encryptable wrapper so stored DEK
shares can be rewrapped for replacement guardians without opening them.

Benefits:

- potentially low traffic for a planned replacement;
- avoids reconstructing the payload or DEK during simple rewrapping.

Fatal limitations:

- rewrapping the same share does not refresh it or stop historical-share
  accumulation;
- a new custody key recreates the forbidden separate key G and can create a
  shortcut around signer-derived A;
- proxy re-encryption adds a new, difficult-to-audit primitive and revocation
  assumptions;
- lost share repair still needs threshold material;
- it does not solve atomic epoch discovery or rollback.

Decision: reject.

## 3.5 Comparative scorecard

| Dimension | A: slot copy | B: dealer rebuild | C: DPSS epochs | D: wrapper/PRE |
|---|---|---|---|---|
| Security | weak against retention | recovery-client trust | strongest under explicit bounds | adds new key/primitive risks |
| Availability | only planned handoff | works from k old records | construction-dependent quorum | does not repair lost shares |
| Complexity | low | medium | very high | high |
| Metadata leakage | low | low; coordinator sees roster | participants learn session pseudonyms | new registry/key relations |
| User interaction | none for planned exit | owner-controlled client preferred | normally none | normally none |
| Guardian coordination | one-to-one | none | all-to-all/logical broadcast | low to medium |
| Signer involvement | must still authorize | two phases | two phases | must authorize |
| Owner involvement | optional | strongly preferred | optional veto | optional |
| Crash tolerance | fragile copy | staged retry | protocol-specific recovery | protocol-specific |
| Byzantine tolerance | none | dealer can corrupt successor | explicit active bound/VSS | unclear/new assumptions |
| Mobile adversary | fails | fresh sharing helps, dealer trusted | designed for it | fails without full refresh |
| Implementation | easy | feasible with current crates | blocked on vetted provider | blocked/new crypto |
| Code compatibility | high | moderate; needs epochs | low; new crypto/state | contradicts A/DEK rules |
| Migration | easy but weak | recovery-equivalent | full protocol-v3 migration | full redesign |
| Operational cost | low | k downloads + n uploads | high interactive traffic | medium |

---

# PHASE 4 — Adversarial review

## 4.1 Attacks on logical-slot copying

An attacker compromises G1, stores its share, waits for G1's replacement,
then compromises G2 in a later year, and repeats. Because the polynomial never
changes, the attacker eventually owns k distinct indices. Copying also cannot
distinguish a guardian that really deleted from one that kept the share. The
candidate fails the primary long-term goal.

## 4.2 Attacks on dealer rebuild

A malicious rotation service legitimately obtains signer-encrypted A shares
and k guardian records. It can recover DEK and plaintext, even if the nominal
code path skips payload decryption. It can also provision inconsistent new
shares and persuade byte-storage guardians to acknowledge records they cannot
cryptographically validate. Atomic activation prevents accidental partial
deployment, but not a malicious dealer. This candidate is acceptable only
when the dealer is an owner-controlled recovery endpoint and its stronger
trust is explicit.

## 4.3 Attacks on naive resharing

Simply having each old guardian Shamir-share its share and asking new
guardians to add subshares is not sufficient:

- a malicious old dealer can use inconsistent subshares;
- a coordinator can equivocate about the qualified dealer set;
- missing complaints can create different new polynomials;
- a partition can make two committees believe different epochs are active;
- old/new cross-committee corruption during handoff requires a construction
  whose proof covers that exact mobile-adversary model;
- published work has found attacks in proposed proactive VSS variants.

Therefore the repository must consume a complete reviewed DPSS protocol, not
assemble a new one from `split_secret`, scalar arithmetic and message glue.

## 4.4 Attacks on the DPSS control plane

### Compromised signer threshold

It can authorize a hostile recovery today. Rotation gives it the additional
ability to authorize a malicious committee and cause denial of service. The
delay and owner veto provide a reaction window; they do not neutralize signer
threshold compromise.

### Malicious guardians silently replace honest guardians

They cannot obtain signer Begin/Activate certificates or the config-witness
activation quorum. DPSS messages without the exact rotation transcript are
discarded.

### Malicious new guardian insertion

The exact successor roster commitment and session keys are bound into the
signer-approved RotationPlan. Changing one candidate changes the transcript.
Selection evidence is advisory; authorization remains a signer-threshold act.

### Malicious coordinator

It receives A and C but no DPSS shares. It cannot forge signer, guardian, DPSS
or witness proofs. It can drop or reorder traffic and cause abort, but the old
epoch remains active. The coordinator is still capable of using A to attempt a
normal recovery, which is why rotation has the same delay/cancellation policy.

### Malicious config store or relay

A relay can deny service but cannot change authenticated inner messages. One
config store cannot activate or roll back an epoch. A fresh client requires a
nonce-bound read quorum from the card-pinned witness set.

### Network partition

No activation quorum means the old epoch remains authoritative. A completed
activation quorum is unique under quorum intersection. Nodes that cannot
obtain an unambiguous certificate fail closed. Availability is sacrificed to
safety.

### Historical shares

All new shares come from an independent epoch sharing of the same DEK. Inputs
from different epochs are rejected at the API, and mathematically do not form
one polynomial. Proactive secrecy still requires fewer than the construction's
corruption bound in every epoch and secure erasure by recovered honest nodes.

### Retained old threshold

If an attacker ever acquires a complete old threshold plus the corresponding
authorization capability and fragments, rotation cannot revoke that knowledge.
A fresh DEK and payload re-encryption are required, which necessarily exposes
plaintext to a trusted owner/recovery endpoint.

## 4.5 Attacks on wrapper/PRE designs

A proxy can transform storage encryption but cannot turn an old Shamir point
into a fresh independent epoch without a real resharing protocol. Former
guardians retain usable points. Adding a custody master key concentrates
authority and violates the required A/DEK separation. The candidate is
discarded.

---

# PHASE 5 — Final architecture

## 5.1 Version and cryptographic state

This is protocol v3 and is not wire-compatible with v2.

```text
ConfigRef {
    config_id,
    payload_generation,
    authorization_epoch,
    guardian_epoch,
    epoch_binding,
}

ActiveGuardianEpoch {
    epoch_ref,
    predecessor_hash,
    guardian_count,
    guardian_threshold,
    dpss_suite,
    dpss_public_commitment,
    guardian_material_root,
    encrypted_recovery_descriptor,
    signer_set_commitment,
    owner_cancel_public_key,
    activation_qc,
}
```

Implementation correction: the earlier draft placed `capsule_hash` inside
`ConfigRef` while also requiring the Recovery Descriptor ciphertext and its
AEAD/KDF context to bind that full reference. Because the ciphertext is itself
inside the capsule, that definition was circular and could not be computed.
Protocol v3 therefore uses a fresh, unpredictable `epoch_binding` in
`ConfigRef`. The actual `capsule_hash` is a separate hash of the canonical
capsule body (which excludes activation certificates and the activation QC);
signer Activate votes and witness records bind that hash. The encrypted
descriptor and per-slot contexts bind `epoch_binding`. This is the smallest
correction and preserves epoch, predecessor, and rollback binding.

For routine guardian rotation:

- payload generation, C, DEK and A remain unchanged;
- guardian epoch increments exactly by one;
- the implemented one-for-one replacement profile retains guardian count and
  threshold; changing erasure parameters requires a separately specified full
  configuration rotation;
- every DEK share is independently refreshed;
- all opaque guardian slots, session keys, wrapping contexts, material roots
  and routes are fresh;
- the Recovery Descriptor is rewritten and resealed under an A-derived key
  bound to the new guardian epoch;
- ciphertext fragments are reconstructed/re-encoded as needed and wrapped in
  fresh epoch storage envelopes so identical bytes are not exposed across
  epochs.

The payload AEAD context binds `payload_generation`, not guardian epoch. The
guardian-share and descriptor contexts bind the full `ConfigRef`.

## 5.2 Roles

### Rotation coordinator

A fresh ephemeral client. It receives signer-encrypted A shares, opens the old
descriptor, selects/routs participants, derives per-guardian unwrap/wrap
grants, reconstructs encrypted C from fragments, and assembles certificates.
In the DPSS path it never receives D_i or DEK.

### Old guardians

They keep the active record intact during preparation. After the release
certificate they may decrypt only their own share, run the old-committee DPSS
role, and send their committed ciphertext fragment to the coordinator.

### New guardians

They run the new-committee DPSS role, receive exactly one new share and one
fragment, wrap the share under their epoch-specific A-derived key, durably
store the record, delete plaintext DPSS state, and sign a preparation receipt.
They never return the wrapped share or full record to the coordinator, because
that coordinator knows A and therefore the wrapping key; they return only the
record commitment leaf needed to assemble the material root.

### Signers

They perform external authorization twice: Begin before the delay and Activate
after the exact new epoch is ready. They maintain durable anti-replay state for
rotation ids and predecessor hashes. Before approving any new recovery or
rotation Begin, they obtain a fresh config-witness read quorum and refuse a
request for an older epoch. After activation they may still issue Release votes
for an exact old-epoch request that was already begun, but never a new old-epoch
Begin.

### Owner

The owner need not be online. The setup-time cancellation key can veto the
exact rotation. It gains no initiation, activation, A, DEK or descriptor
authority.

### Config witnesses

At least `3f + 1` independently administered, card-pinned witnesses store only
the highest activated capsule for an opaque config id plus predecessor/epoch
locks. A write or fresh read quorum is `2f + 1`. They expose no list operation
and receive no plaintext guardian roster.

## 5.3 Trigger conditions

A proposal may be raised by:

- a planned exit;
- repeated failed private custody checks;
- signed invalid or `not_found` responses;
- persistent operational unavailability;
- provider/geography concentration policy;
- a fixed proactive refresh schedule;
- a signer/owner security-upgrade request.

Triggers are evidence and policy inputs only. They do not authorize rotation.
Routine schedules should be jittered within public epochs but independent of a
particular recovery event.

## 5.4 Candidate selection

The coordinator selects a complete successor committee before requesting
signer votes. Selection should enforce:

- distinct operator and failure domains;
- geographic/provider diversity;
- supported protocol/DPSS suite and software version;
- current capacity and audit history;
- no duplicate long-term guardian key;
- no candidate controlled by the exiting operator where policy forbids it.

The exact pseudonymous candidate keys and session routes are committed in the
RotationPlan. They are distributed only inside end-to-end encrypted messages.
Signers approving rotation may learn these pseudonyms; the public and config
witnesses do not.

## 5.5 Canonical messages

Every transcript uses explicit domain separation and length-prefixed fields.
All include protocol version, full ConfigRef, rotation id, predecessor capsule
hash, recipient keys and expiry. Every message after the descriptor-open intent
also binds the exact participant/roster commitments; the intent instead binds
immutable selection constraints and cannot authorize guardian action.

```text
RotationIntent
SignerRotationIntentContribution
RotationPlan
SignerRotationBeginVote
BeginRotationCertificate
OwnerRotationCancelCertificate
OwnerRotationCancelAck
SignerRotationReleaseVote
RotationReleaseCertificate
OldShareUnlockGrant
NewShareWrapGrant
DpssProtocolMessage             // construction-defined, transcript-bound
CiphertextFragmentContribution
NewGuardianPreparedAck
OldGuardianHandoffAck
RotationReadyCertificate
SignerRotationActivateVote
RotationActivateCertificate
WitnessActivationAck
WitnessRotationCancelAck
EpochActivationQC
EpochReadChallenge
WitnessEpochReadResponse
RetirementNotice
RetirementAck
AbortRotationCertificate
```

`DpssProtocolMessage` must be owned by the selected maintained DPSS provider;
the project defines only its authenticated envelope and session binding.

## 5.6 State machine

Rotation uses a separate state machine and does not add alternate recovery
states:

```text
Proposed
  -> DelayPending
  -> Preparing
  -> Ready
  -> Activating
  -> Active
  -> Draining
  -> Retired

Any state before Active -> Aborted
```

At most one child of an ACTIVE epoch can obtain an activation QC. PREPARING
state never changes recovery authority.

## 5.7 Complete protocol

### Step 1 — Authorize descriptor opening

The coordinator creates a fresh rotation-recipient KEM keypair and a
`RotationIntent` bound to the read-quorum-confirmed predecessor, reason,
allowed membership/threshold change, allowed DPSS suites, expiry, nonce and
recipient. Signers verify the fresh witness responses and return intent
contributions with their A shares encrypted to that exact recipient and intent.

A signer threshold lets the coordinator reconstruct A and open the old sealed
descriptor. This is necessary because the private old roster and routes are
otherwise unavailable. The intent is deliberately not a Begin certificate:
no guardian accepts it, no delay starts, and it authorizes no record, unwrap or
DPSS operation.

### Step 2 — Propose the exact plan, Begin and delay

After learning the old roster, the coordinator selects the complete successor
committee and creates the exact `RotationPlan`. Signers verify that it conforms
to the intent, current epoch, candidate policy and absence of a prior rotation
lock. Their votes form `BeginRotationCertificate`, cryptographically binding
the old and new roster commitments, thresholds, session keys and deadlines.

The coordinator can derive wrapper keys at this point, but it has no guardian
records or D shares and the Begin certificate alone grants no custody
operation.

Every old guardian validates the Begin certificate, records a monotonic
`not_before`, and stores an exact rotation-id tombstone/replay record. The
delay is at least the configured recovery delay. No guardian unwraps a share,
sends a fragment or begins DPSS during this window.

The owner may send `OwnerRotationCancelCertificate`. Honest guardians persist
the cancellation before acknowledging. Completion requires enough old
guardian acknowledgements to leave fewer than the DPSS minimum handoff quorum.

### Step 3 — Release authorization

After each old guardian's local delay, signers issue fresh Release votes for
the unchanged plan. No old guardian unwraps a share or sends a fragment without
both its persisted Begin, elapsed delay and valid Release certificate.

### Step 4 — Issue per-guardian grants, not DEK

The coordinator uses the A reconstructed for the descriptor-open intent to
derive:

```text
old K_i = HKDF(A, "gp/guardian-dek-share/v3" || old ConfigRef || old index)
new K_j = HKDF(A, "gp/guardian-dek-share/v3" || new ConfigRef || new index)
```

Each K value is encrypted only to the corresponding guardian's fresh session
recipient and bound to the exact rotation. The coordinator never sends A.
Although it can derive these K values before Begin, honest guardians accept
them only with the persisted exact Begin, elapsed local delay and exact Release
certificate. This is the same kind of guardian-enforced delay boundary used by
recovery; the delay does not claim to keep A from the intent-authorized
coordinator.

### Step 5 — Repair encrypted payload fragments

At least k old guardians send their committed F_i to the coordinator under the
release certificate. The coordinator verifies their record Merkle proofs,
reconstructs C, and deterministically re-encodes F'_j with the unchanged n/k
parameters. It must reproduce the payload generation's stable ciphertext-
fragment Merkle root. Each successor verifies its exact fragment/index proof
against that root before preparation. The coordinator never decrypts C.

If fewer than k valid fragments exist, automatic rotation aborts. There is no
way to regenerate C from less than k under the current erasure code.

### Step 6 — DPSS handoff

Each qualified old guardian:

1. opens only its K_i grant;
2. decrypts only its E_i into zeroizing D_i memory;
3. verifies the exact DPSS session and qualified-set transcript;
4. runs the reviewed old-committee role;
5. sends only construction-defined encrypted subshares/proofs;
6. retains its old durable record until activation;
7. erases D_i, K_i and ephemeral subshare state after the handoff completes or
   aborts.

Each new guardian:

1. runs the reviewed new-committee role;
2. rejects any subshare or broadcast not bound to the exact plan;
3. obtains and verifies one new D'_j;
4. encrypts it under new K_j with full ConfigRef/index associated data;
5. stores E'_j, F'_j, policy, integrity proofs and fresh opaque routes;
6. discloses only the prepared-record commitment leaf, then locally attaches
   the coordinator-computed Merkle root/path after verifying it;
7. erases D'_j, K_j and DPSS ephemeral state;
8. signs `NewGuardianPreparedAck`, including the exact material root, only
   after an atomic durable write.

The selected DPSS construction must guarantee either one consistent successor
sharing of the same DEK or abort. Master Recovery does not define its own
complaint, disqualification or polynomial arithmetic rules.

### Step 7 — Ready

The coordinator requires all advertised new guardians to produce valid
Prepared acknowledgements. Activating “8 guardians” with only five stored
records is forbidden. A failed candidate is replaced while the old epoch is
still active, and the successor commitment is regenerated.

The Ready certificate commits to every prepared record leaf, the new encrypted
descriptor, the DPSS result commitment, all thresholds and all ack digests.

### Step 8 — Activate atomically

Signers inspect the Ready certificate and produce Activate votes. A threshold
forms `RotationActivateCertificate` over the exact new capsule hash.

The coordinator submits it to the config witnesses. An honest witness:

- accepts only successor `guardian_epoch + 1`;
- checks the predecessor hash equals its durable current value;
- signs at most one child of that predecessor;
- verifies the signer activation certificate;
- stores the new capsule before returning its ack.

`2f + 1` witness acks form `EpochActivationQC`. This QC, not a coordinator
message or timeout, makes the new epoch ACTIVE.

### Step 9 — Drain and retire

Old guardians stop accepting new Begins after observing the activation QC, but
continue exact old-epoch requests that were already DelayPending. Those
requests keep their original monotonic delay, expiry, release votes and owner
cancellation path. They never migrate.

An isolated old guardian cannot start a stale recovery because an honest signer
threshold will not create a new old-epoch Begin certificate. Signers and owner
control storage retain the state and private routes needed to finish or cancel
only the already-begun draining requests.

After the maximum old request expiry window, honest old guardians erase old
records and secret DPSS state, retain compact stale-epoch/replay tombstones,
and sign retirement acknowledgements. Missing retirement acknowledgements are
health evidence, not proof of deletion failure.

## 5.8 Fresh-client discovery and rollback prevention

The Recovery Card v3 pins config-witness public keys and fault parameter f.
A fresh client sends a random nonce to at least `2f + 1` witnesses. Each signs:

```text
config_id || client_nonce || highest_guardian_epoch || capsule_hash
```

The client selects the highest valid activated epoch returned by the quorum,
verifies its signer activation certificate and witness QC, and fails closed on
conflicting same-epoch hashes.

With `3f + 1` witnesses and write/read quorums of `2f + 1`, every completed
write intersects every read in at least `f + 1` witnesses, including an honest
one. A replayed old response cannot answer the fresh nonce. If the client is
eclipsed and cannot reach a quorum, recovery is unavailable rather than rolled
back.

The current three mirrored, unauthenticated-by-card stores cannot tolerate one
Byzantine store under this model; four witnesses are required for f=1.

## 5.9 Recovery and cancellation during transition

- PREPARING has no recovery authority; old remains ACTIVE.
- a request created before activation binds the old epoch and drains there;
- a request created after read-quorum discovery binds the new epoch;
- old and new shares are never combined;
- activation does not shorten or restart an old request's delay;
- a new epoch does not inherit an old Begin or Release certificate;
- owner cancellation of an old request is retained by old guardians through
  draining;
- owner cancellation of the rotation aborts the rotation but does not cancel
  unrelated recovery requests;
- after activation there is no rollback operation. A correction is a new
  forward rotation.

## 5.10 Failure behavior

Before activation, any missing DPSS quorum, invalid proof, missing fragment,
failed provisioning, coordinator crash, timeout, partition, cancellation or
ambiguous transcript causes ABORT. The old epoch remains ACTIVE.

After activation, new guardians already hold all n records. A node that missed
the activation message learns it from a witness QC. Conflicting valid-looking
QCs cause fail-closed emergency escalation; honest witnesses cannot create
both under the stated bound.

## 5.11 Final-design requirement map

| Required element | Exact design answer |
|---|---|
| 1. State before rotation | A and DEK are separately shared; guardians hold committed `E_i` and `F_i` in one ACTIVE epoch. |
| 2. Triggers | Planned exit, health evidence, compromise, diversification, policy or scheduled refresh creates only a proposal. |
| 3. Authorization | Signer-threshold descriptor-open intent, exact Begin, delay, Release and final Activate; owner key may veto. |
| 4. Replacement selection | Complete policy-checked successor roster is committed before Begin. |
| 5. Messages | The canonical message set in section 5.5 binds the exact plan, epoch, recipient and expiry. |
| 6. Material received | Coordinator gets A/C; each old guardian gets only `K_i`; each new guardian gets one DPSS share, `K'_j`, one fragment and policy. |
| 7. Material never learned | No guardian/signers/witness/auditor learns plaintext or DEK; DPSS coordinator never learns D shares/DEK. |
| 8. Missing material repair | Reconstruct C from k committed fragments; reconstruct no missing old D share—DPSS proceeds only with its qualified old quorum. |
| 9. Share migration | A vetted DPSS creates an independently randomized sharing of the same DEK. |
| 10. Provisioning proof | Every advertised new guardian signs only after an atomic durable write; all n acks are required. |
| 11. Activation | Signer Activate certificate plus `2f+1` witness acks forms the unique activation QC. |
| 12. Retirement | Old epoch drains only pre-existing requests, then honest parties erase records and retain replay tombstones. |
| 13. Rollback prevention | Card-pinned witnesses, predecessor locks, intersecting quorums and nonce-bound reads. |
| 14. Stale shares | Epoch-bound and never mixed; retained same-epoch threshold remains an unavoidable weakness. |
| 15. Versions/epochs | Payload, authorization and guardian generations are separate; routine rotation changes only guardian epoch. |
| 16. Concurrent recovery | PREPARING leaves old ACTIVE; each request stays on the epoch where it began. |
| 17. Concurrent cancellation | Exact request cancellation remains on its epoch; owner rotation cancellation independently aborts pre-activation. |
| 18. Metadata resistance | Sealed descriptor, opaque witness id, private fixed-cell routes and no public roster; residual timing/session-pseudonym leakage is stated. |
| 19. Failure behavior | Any pre-activation ambiguity aborts; any post-activation ambiguity fails closed. |
| 20. Partial failure recovery | Old ACTIVE records are untouched; replace the failed candidate and restart the exact successor plan. |
| 21. Assumptions | Signer threshold, DPSS bounds, secure erasure, authenticated private channels, witness fault bound, KEM/AEAD/signature security. |
| 22. Weaknesses | A is exposed to an ephemeral coordinator, deletion is unprovable, DPSS may be unavailable, quorums can DoS, and rotation cannot revoke learned DEK/plaintext. |

---

# PHASE 6 — Security argument

## 6.1 Confidentiality

In the production path, the coordinator learns A, the hidden routes and C, but
no D shares or DEK. An old/new guardian learns one epoch share and
session-scoped pseudonymous DPSS participants, not plaintext, A or full stable
recovery routing. Signers learn rotation intent and candidate pseudonyms but
not DEK or plaintext. Witnesses learn only opaque config id, epoch timing,
counts, commitments and sealed capsule bytes.

The existing combined-threshold assumption remains: a signer threshold can
authorize a hostile recovery, and a sufficiently malicious guardian set can
violate policy. Rotation does not turn this into a stronger claim.

## 6.2 Mobile-adversary argument

Every successful epoch contains an independently randomized sharing of the
same DEK. The DPSS proof must guarantee privacy when the adversary corrupts no
more than its stated bound in each old/new handoff. Honest recovered nodes
erase old material. Consequently, observations from epoch 1, 4 and 9 do not
form one valid interpolation set.

This guarantee fails if:

- the adversary obtains the threshold within any one epoch;
- honest nodes cannot securely erase old shares/keys;
- the DPSS construction's old/new cross-committee corruption bound is
  exceeded during handoff;
- the DPSS implementation or authenticated channels are broken.

## 6.3 Atomicity and rollback

The old record is never deleted during PREPARING. All new records exist before
Activate. Witness predecessor locks and intersecting quorums admit at most one
activated child. A fresh nonce-bound read quorum intersects the completed
activation quorum, so an old capsule cannot be accepted while the fault and
reachability assumptions hold.

Without online trusted/quorum state, a brand-new client cannot distinguish a
valid old signed capsule from the latest signed capsule. Hash chains alone do
not solve this freshness problem. The witness assumption is therefore
necessary unless users manually update the Recovery Card after every rotation.

## 6.4 Metadata argument

No public guardian list or per-owner rotation log is introduced. Config
witnesses use non-enumerable opaque ids and fixed-size sealed capsules. DPSS
and audit traffic use the same STRONG-mode cell format, epochs, cover traffic,
rotating mailboxes and multi-hop routes as other traffic.

Unavoidable additional leakage:

- config witnesses can see that one opaque config changed epoch;
- participating signers know they approved a rotation;
- rotation participants learn session-scoped pseudonymous committee
  membership needed by the DPSS construction;
- a participating old/new guardian knows its slot is being handed off;
- a global observer may correlate unusually large multi-party handoff traffic;
- repeated rotations can reveal cadence despite cover traffic.

The design does not claim to hide these facts perfectly.

## 6.5 Denial of service

Auditors, relays and minority guardians can trigger noise or abort preparation,
but cannot retire the old epoch. A signer threshold can authorize destructive
policy and is therefore an availability trust boundary. Witnesses can block
activation by withholding a quorum. These are explicit availability
assumptions, not cryptographic confidentiality failures.

## 6.6 What rotation cannot repair

- knowledge of plaintext or DEK already obtained by an attacker;
- a complete retained old-epoch threshold;
- loss of more material than permits C and DEK recovery/handoff;
- loss of the owner cancellation key;
- signer-threshold compromise;
- a global network denial that prevents all required quorums;
- physical inability to erase old disks/backups.

Compromise response requiring revocation uses a full configuration/key
rotation: reconstruct plaintext only on a trusted owner/recovery client,
generate fresh DEK and A as required, re-encrypt, and issue a new Recovery
Card/config generation.

---

# Storage health and proof of custody

## Commitment is not possession

The existing Merkle root proves that returned bytes match setup bytes. A
guardian can retain only the root and still pass no meaningful possession
test. A signature over the root is an inventory commitment, not proof that the
record remains retrievable.

## Recommended first production mechanism: private sampled retrieval

At provisioning, encode the encrypted custody body (`E_i`, `F_i` and padding)
into fixed-size blocks and build a per-record Merkle tree. Domain-separate each
leaf with a random per-slot audit-domain identifier and block index. Bind the
resulting root and audit-domain identifier to ConfigRef inside the sealed
descriptor and guardian policy; the external watchtower receives neither
ConfigRef nor the binding.

Assign one unlinkable per-slot watchtower capability containing only:

```text
one rotating audit mailbox
one session-scoped slot capability
record block count and block root
guardian verification key
no owner identity, config id, or other guardian routes
```

On a fixed cover schedule, the watchtower chooses unpredictable block indices
and a nonce. The guardian returns the exact blocks, Merkle paths and a signed
transcript encrypted to the audit recipient. Occasional full-record retrievals
provide stronger evidence for these small records. A watchtower must not audit
k slots for one config; otherwise it becomes a collector of threshold encrypted
custody material.

This is a probabilistic sampled-possession check, not a formal proof of
retrievability and not proof of local unique storage. A guardian may fetch data
from another service before responding. If formal PoR is later required, select
an independently reviewed private-verifier construction and analyze its PQ,
metadata and tag-key assumptions before adding it.

The verifier necessarily learns the challenged blocks of encrypted custody
material and their positions. Repeated challenges can eventually reveal the
whole encrypted custody body. That does not reveal plaintext without the
separate signer-derived A path, but it enlarges the set of parties holding
encrypted recovery material. Therefore one watchtower must never span multiple
slots of one config, capabilities must be unlinkable, responses must use
end-to-end encryption and retention limits, and a deployment that cannot
enforce that separation should omit third-party sampled audits. An
owner-controlled health client may instead perform occasional full retrievals.

## Health decisions

- one timeout: no rotation, retry through other routes;
- repeated timeouts across epochs: degrade health score and directly probe;
- valid sampled responses: evidence of sampled possession at those times;
- signed invalid proof/bytes: objective cryptographic fault;
- signed `not_found`: objective admission of loss;
- no response: operational evidence only, because the network may be at fault.

Auditors never authorize rotation. Their reports feed the proposal policy,
which still needs signer Begin/Activate certificates and the normal delay.

## Slashing boundary

Potentially objective evidence:

- two guardian signatures equivocating on one epoch/session;
- a signed invalid DPSS contribution whose invalidity is publicly checkable by
  the selected construction;
- a signed Prepared acknowledgement followed by a signed `not_found` for the
  same active record;
- a signed contribution whose bytes fail the committed Merkle proof;
- two config-witness signatures for conflicting children of one predecessor.

Not objectively slashable by itself:

- timeout, packet loss or an auditor's assertion;
- low uptime score;
- absence during a partition;
- failure to prove physical deletion;
- a failed end-to-end recovery without attributable signed evidence.

The current project explicitly excludes implementing staking/slashing; this
section defines evidence semantics only.

---

# Concrete failure scenarios

## A. Planned guardian exit

Start a full DPSS refresh while all old guardians are healthy. Replace the
departing member in the committed successor roster. Activate only after all
new records are prepared. The departing guardian drains old requests and then
deletes. Do not use exact-share copying as the final step.

## B. Sudden disappearance

Mark the guardian unhealthy after repeated probes, select a replacement, and
run DPSS with the remaining old handoff quorum. The missing guardian is not
needed if the selected construction's quorum remains satisfied.

## C. Guardian lost its stored material

Treat it as absent. At least k valid fragments are required to reconstruct C,
and the DPSS suite's old quorum is required to refresh DEK sharing. A signed
`not_found` is attributable evidence; an unsigned timeout is not.

## D. Guardian detected as malicious

Exclude it from the qualified old dealer set if the DPSS protocol permits and
from the successor roster. Preserve signed invalid messages as evidence. Never
lower thresholds to make the handoff finish.

## E. Three guardians disappear in 5-of-8

Exactly five valid old records are sufficient for ordinary recovery, but not
automatically for active-secure DPSS. If the vetted suite proves handoff with
those five and its fault assumptions hold, proceed urgently. Otherwise the
automatic DPSS path stops. An owner-assisted recovery-equivalent dealer rebuild
is the fallback; without it, recovery remains possible but safe autonomous
rotation is unavailable.

## F. Replacement fails during provisioning

No activation occurs. Old stays ACTIVE. Select another candidate and generate
a new successor commitment/plan or abort. Never retire first and repair later.

## G. Rotation while recovery is in delay

The recovery remains bound to the old epoch and its original `not_before`.
After activation, old guardians enter DRAINING and may finish that exact
request until expiry. No certificate migrates to the new epoch.

## H. Partition creates conflicting views

Neither side can complete a second witness activation quorum under the fault
bound. A side without a quorum fails closed. If one QC completed, it is the
unique active successor; lagging nodes converge when they can query witnesses.

## I. Historical shares from multiple epochs

They are rejected by epoch binding and are shares of independent polynomials.
They do not combine if the attacker remained below the DPSS corruption bound
in every epoch and honest old material was erased.

## J. Malicious old guardian refuses deletion

Its old share remains useful only with enough shares from that same old epoch
and the old authorization/material path. Deletion cannot be proven. Fresh
epochs limit one retained share's usefulness but cannot revoke an old
threshold.

## K. Auditor falsely reports failure

The report lowers a health score or triggers a direct probe. It cannot produce
signer certificates, DPSS messages or witness QC. No slashing occurs without
attributable signed cryptographic evidence.

## L. Owner offline for years

A signer threshold can authorize and activate rotation after the normal delay.
The owner need not participate. If the cancellation key is unavailable, there
is no veto—exactly the existing recovery limitation. If the DPSS quorum is
lost, user/owner-assisted recovery becomes unavoidable.

---

# PHASE 7 — Integration plan

## 7.1 Authoritative documentation

Before code:

1. amend `MASTER_PROMPT.md` to define protocol v3 Guardian Epochs, the limited
   rotation-participant metadata disclosure, the DPSS provider/security model,
   and config witnesses;
2. update `PROTOCOL.md`, `SECURITY.md`, `METADATA_RESISTANCE.md` and
   `ARCHITECTURE.md` in source-of-truth order;
3. retain v2 as immutable/recovery-only. Do not silently reinterpret v2
   `config_version`.

## 7.2 `gp-types`

Add:

- `ConfigRef`, `GuardianEpoch`, `RotationPlan`, all vote/certificate/ack
  structs, `EpochActivationQc`, witness read/write responses;
- separate `RotationState` without changing the required recovery states;
- `DpssSuiteId`, DPSS commitment/reference types owned as opaque bytes;
- `RecoveryRequest.epoch_ref`;
- `ConfigCapsuleV3` with predecessor and activation QC;
- `RecoveryCardV3` with witness keys/fault bound;
- `GuardianPolicyV3` with active/prepared/draining epoch state;
- per-slot custody-audit commitment/capability types.

Never serialize private roster data into the public capsule.

## 7.3 `gp-wire`

Add canonical, domain-separated transcripts for every rotation and witness
message. Bind full ConfigRef, plan hash, exact old/new actor index, session
recipient, nonce, expiry, predecessor and capsule hash. Add fixed maximum sizes
and reject duplicate actor ids/acks.

## 7.4 `gp-crypto`

Add only thin wrappers for the selected reviewed DPSS library and maintained
primitives. Required interface:

```text
begin_old_share(...)
accept_dpss_message(...)
finalize_new_share(...)
verify_dpss_result(...)
zeroize_session(...)
```

No local field arithmetic, polynomial commitments, complaint rules or hybrid
combiners. Add epoch-specific HKDF and AEAD contexts and block-Merkle helpers.

If no suitable library is selected and compiled, stop here rather than falling
back silently to dealer reconstruction.

## 7.5 `gp-core`

Add deterministic `RotationMachine` and `EpochWitnessMachine`:

- explicit transition table;
- one-child predecessor lock;
- monotonic delay inputs;
- cancellation tombstones;
- abort-before-activation behavior;
- drain deadlines;
- fail-closed conflict events.

Keep all clocks, entropy, storage and network outcomes injected.

## 7.6 `gp-storage`

Persist atomically:

- ACTIVE and optional PREPARED guardian records side by side;
- DPSS session journal and qualified-set digest;
- rotation/replay/cancellation tombstones;
- activation QC and drain deadline;
- witness predecessor/highest-epoch locks;
- signer rotation votes and anti-equivocation locks;
- audit challenge/response replay state.

Secret DPSS journals, unwrap/wrap grants and plaintext shares must be zeroizing
and securely erased on completion/abort to the extent the platform supports.

## 7.7 `gp-network`

- add rotation coordinator CLI and mailbox requests;
- add guardian PREPARE/DPSS/ACTIVATE/ABORT/RETIRE handlers;
- add signer Begin/Release/Activate rotation handlers;
- replace write-once config store behavior with authenticated witness APIs;
- add nonce-bound quorum reads and write-QC collection;
- provision fresh pairwise DPSS mailboxes through metadata-resistant routes;
- do not put config id, guardian index or rotation id in outer transport headers;
- retain v2 endpoints separately for recovery-only compatibility.

## 7.8 `gp-sim`

Use the same `RotationMachine` and DPSS adapter as the network path. Add
virtual old/new committees, partitions, crash points, malicious subshares,
historical compromise sets, secure-erasure toggles, witness faults, audit
traffic and rotation cover cells.

The simulator may know real committee relations for visualization; actor and
observer objects must not receive privileged mappings.

## 7.9 Recovery Card and migration

V2 cards cannot authenticate mutable latest state. Safe migration requires a
recovery-equivalent, owner-approved operation that emits a new v3 Recovery Card
with witness keys. There is no transparent backward-compatible upgrade.

V2 configurations remain recoverable and immutable. Users must explicitly
save the v3 card once. Later guardian rotations keep the same v3 card.

## 7.10 GUI/UX

Normal path:

```text
Guardian unhealthy. Replacement in progress.
Preparing 8/8 guardian records…
Guardian epoch 12 active. 8/8 healthy. No action required.
```

Expose:

- current/previous guardian epoch and health count;
- PREPARING versus ACTIVE clearly;
- delay/cancellation window;
- “old epoch remains recoverable” during preparation;
- exact reason automatic rotation stopped;
- a critical action only when DPSS/recovery quorum is no longer available.

Never display “proof of storage” for a Merkle commitment or sampled audit.

## 7.11 Implementation order

1. authoritative v3 specification and threat-model review;
2. DPSS library selection, independent audit evidence and compatibility PoC;
3. types/transcripts plus deterministic state machines;
4. config-witness register and rollback tests;
5. DPSS adapter with test-only in-memory transport;
6. fragment repair and prepared-record storage;
7. network coordinator/handlers;
8. simulator/adversarial controls;
9. custody sampling and GUI;
10. migration tooling and external review.

---

# PHASE 8 — Tests

## 8.1 Deterministic unit tests

| Test | Protected invariant |
|---|---|
| exact rotation transition table | no hidden activation path |
| invalid predecessor/version rejected | no rollback or skipped epoch |
| signer transcript field mutation | exact plan/recipient binding |
| duplicate signer/guardian/witness ids rejected | no quorum inflation |
| rotation cancel before Begin | cancellation tombstone survives reordering |
| cancellation after release | not falsely retroactive |
| old/new HKDF contexts differ | no cross-epoch wrapper reuse |
| old/new shares reject mixing | exact epoch binding |
| DPSS result verification failure | no invalid successor activation |
| custody block/proof mutation | sampled response integrity |

## 8.2 Property tests

- for supported n/k/f values, no sequence of events activates without all
  required certificates and receipts;
- any abort before activation leaves the old epoch recoverable;
- no two different children of one predecessor both obtain witness QCs under
  at most f faulty witnesses;
- every completed write quorum intersects every read quorum in an honest
  witness;
- shares sampled below the DPSS bound in every epoch reveal no accepted
  reconstruction, while each complete new threshold reconstructs the same DEK;
- arbitrary mixed-epoch subsets are rejected before interpolation;
- deterministic seed produces an identical multi-epoch trace.

## 8.3 Multi-node integration tests

1. planned 5-of-8 -> 5-of-8 replacement without plaintext reconstruction;
2. one missing old guardian and one malicious subshare dealer;
3. reject a routine rotation that attempts to change n/k; parameter changes
   are reserved for a separately specified full configuration rotation;
4. reconstruct C from k fragments and provision all new fragments;
5. all new Prepared acks -> activation QC -> old drain -> retire;
6. new guardian crash before durable ack -> old remains ACTIVE;
7. coordinator crash at every persisted step and restart/retry;
8. guardian reboot during rotation delay -> fail closed;
9. witness crash/restart preserves predecessor lock;
10. fresh client finds latest epoch through a nonce-bound read quorum.

## 8.4 Adversarial tests

- replay old Begin/Release/Activate certificates;
- substitute new guardian, index, route, key or threshold;
- old guardian sends inconsistent DPSS messages;
- new guardian signs ack before durable storage (fault injection);
- malicious coordinator withholds final messages;
- two concurrent rotations from one predecessor;
- partition signers, guardians and witnesses into conflicting views;
- Byzantine witnesses return stale, invented-high and same-epoch-conflicting
  capsules;
- accumulate historical shares across many epochs;
- disable secure erasure and demonstrate the exact weakened claim;
- malicious old guardian retains material;
- malicious auditor sends false reports and replayed challenges;
- rotate during recovery Begin, delay, release and cancellation;
- cancel rotation immediately before activation;
- attempt rotation to bypass recovery delay;
- repeated rotations under STRONG mode and measure observer correlation.

## 8.5 Completion gates

Implementation is not complete until evidence shows:

- plaintext instrumentation never fires during the DPSS rotation path;
- no process logs/serializes D_i, DEK, unwrap keys or DPSS private state;
- DPSS upstream test vectors and this adapter's cross-node vectors pass;
- all crash points preserve either old ACTIVE or unique new ACTIVE state;
- witness rollback/fork tests cover fresh-client bootstrap, not only clients
  with local version memory;
- real network and simulator use the same rotation state machine;
- dependency and security audits pass with all warnings dispositioned;
- metadata observer receives no privileged real/dummy or roster mapping;
- an external cryptographic review approves the exact DPSS integration.

---

# PHASE 9 — Self-critique and revision check

## 9.1 Hidden assumptions

The largest hidden assumption would be to write “use DPSS” as if it were one
interchangeable primitive. It is not. The production claim depends on a named
construction whose proof covers dynamic old/new committees, active faults,
asynchrony or the deployment's actual synchrony bound, cross-epoch mobile
corruption, verifiable same-secret transfer and crash recovery. Until a
maintained implementation of that exact construction passes review, Candidate
C is an architecture target, not working cryptography.

The second large assumption is secure erasure. Refresh prevents historical
accumulation only for honest parties that actually delete old shares and
ephemeral DPSS state. Backups, swap, crash dumps, logs and compromised firmware
can invalidate that assumption. The design therefore never equates retirement
acknowledgements with proof of deletion.

The third is online freshness. Config witnesses are a new distributed trust
and availability layer. They do not receive secret material or authorization
power, but a quorum can block progress and the Byzantine bound is necessary for
unique latest-epoch discovery. A deployment unwilling to accept that layer
must require the user to update a trusted Recovery Card after every rotation;
there is no cryptographic third option for a stateless fresh client.

## 9.2 Can an old guardian or historical-share collector break it?

One malicious old guardian can retain its share, withhold messages, equivocate
or force an abort. It cannot cause retirement, choose its replacement, forge a
new epoch or combine its retained point with independently refreshed points.
A construction-specific malicious old quorum may violate DPSS safety or
availability; its exact bound must be stated, tested and exposed in policy.

If an adversary ever retains k shares from one epoch, that epoch's DEK is
compromised forever. Rotation of the same DEK does not heal it. If the
adversary remains below the DPSS corruption bound in each epoch and honest
parties erase, shares collected in different epochs are useless together. This
is the precise proactive claim—nothing stronger.

## 9.3 Can a partition or half-completed transition destroy recovery?

Before the activation QC, no old durable record is removed and PREPARED state
has no recovery authority. A partition can therefore abort or delay rotation,
not lower the active threshold. Intersecting witness quorums prevent two
successors under the stated fault bound. After activation, a partitioned old
guardian might not yet know it is stale, but honest signers will not issue a
new old-epoch Begin after their own fresh quorum read. Already-begun requests
remain deliberately drainable. A client unable to get an unambiguous quorum
stops.

Requiring all n Prepared acknowledgements is intentionally conservative. It
reduces rotation liveness and an acknowledgement proves only that the guardian
claimed a durable write, not that it will remain available. This is preferable
to activating a nominal 8-member epoch that began with fewer than eight
records; post-activation audits and ordinary recovery tests remain necessary.

## 9.4 Can rotation become authorization or secret recovery?

It creates a new exposure: after a signer threshold approves the narrow intent,
the ephemeral coordinator reconstructs A more often than recovery alone would.
A opens the descriptor and derives all wrapper keys, so compromise of that
coordinator is serious even though it receives no D shares in the DPSS path.
Rotation messages use a separate domain and grant only per-slot DPSS
operations; guardians must never treat an intent or Rotation certificate as a
Recovery certificate or return `E_i` to the coordinator. This limits, but does
not erase, the increased A-exposure risk.

A compromised signer threshold can already authorize hostile recovery. It can
also authorize a hostile successor committee. The normal delay and setup-time
owner veto are the only independent checks; rotation does not claim to survive
that threshold plus an absent owner. The dealer fallback reconstructs DEK and
is recovery-equivalent by design, so unattended infrastructure must never
select it automatically.

## 9.5 Does it leak topology or add central points of failure?

DPSS participants may learn the session's pseudonymous participant keys, and
large coordinated traffic may be correlated. That is weaker than the current
ideal in which an individual guardian knows only one opaque slot. Operator
identities, stable routes and the owner mapping remain hidden, but this still
requires an explicit metadata-specification amendment rather than a claim of
no leakage.

The witnesses are not one trusted third party: confidentiality and rotation
authorization do not depend on any one of them, and a Byzantine minority
cannot fork the epoch. They are nevertheless a new quorum availability
dependency. The coordinator is replaceable from its persisted signed
transcript and cannot activate by itself. The chosen DPSS broadcast/agreement
service may introduce further quorum dependencies that must be counted rather
than hidden behind the adapter.

## 9.6 Is this actually better than asking the owner to rebuild?

Yes, but only after the implementation gate is satisfied. Routine healthy-set
maintenance can then refresh shares without plaintext, without DEK at one
participant, without a new Recovery Card and without an online owner. It also
adds proactive protection that an exact-share copy lacks. The price is much
greater protocol, metadata and availability complexity.

The owner rebuild remains better in rare cases where the DPSS handoff quorum
is gone, a new DEK is required, v2 must be migrated, or the DPSS provider does
not meet review. In those cases user interaction is cryptographically or
operationally unavoidable: the client is exercising recovery-equivalent power
and must be owner-controlled. Presenting that path as autonomous rotation
would be the dangerous simplification this design is intended to avoid.

## 9.7 Revision outcome

This self-critique produced four hard gates already incorporated above:

1. no DPSS implementation without a named, reviewed, maintained provider;
2. fresh witness reads by signers prevent new stale-epoch Begin certificates;
3. third-party sampled audits explicitly disclose sampled encrypted custody
   bytes and must be isolated per slot or omitted;
4. v2 migration and no-quorum fallback are explicitly owner-controlled and
   recovery-equivalent.

With those limits, Staged Verifiable Guardian Epochs remains the strongest
defensible target. Without them, Candidate B is the only currently
implementable safe mechanism and should not be described as proactive.

---

# Critical-question ledger

1. Replace without plaintext: DPSS refresh DEK shares; reconstruct/re-encode C.
2. Without DEK: yes only through reviewed DPSS; dealer fallback reconstructs it.
3. Without authorization material: not under current A-wrapping; coordinator
   reconstructs A, guardians receive only per-slot grants.
4. Existing architecture: dealer rotation only.
5. Smallest strong change: guardian epochs + DPSS + witness freshness.
6. New guardian material: one DPSS share, one A-derived wrap grant, one repaired
   fragment, policy/proofs and fresh routes.
7. Initiator: anyone may propose; no proposal authorizes.
8. Authorization: signer threshold Begin and Activate certificates.
9. Autonomous guardians: no.
10. Signers: mandatory in both phases.
11. Owner: optional veto, not normally required.
12. Owner offline: signer-authorized rotation continues without veto.
13. Replaced guardian lost data: use remaining DPSS/fragment quorums.
14. Silent disappearance: health monitoring proposes replacement.
15. Healthy guardians required: at least k for C plus the DPSS suite's old
    handoff quorum.
16. Recovery threshold enough: not necessarily; DPSS bound is separate.
17. Malicious subset replacement: lacks signer and witness certificates.
18. Malicious insertion: exact roster commitment is signer-bound.
19. Rollback: nonce-bound Byzantine witness read quorum.
20. Replay: rotation id, predecessor, epoch, nonce and durable tombstones.
21. Exact binding: full ConfigRef and plan hash in every transcript.
22. Latest discovery: card-pinned `2f+1` witness read quorum.
23. Descriptor rewrite: yes, reseal for every guardian epoch.
24. Abstract routing: stable config locator; all guardian routes remain inside
    the rewritten sealed descriptor.
25. Metadata: sealed fixed-size capsules, opaque ids, private DPSS transport.
26. Registry leakage: witnesses see opaque config epoch timing, never roster;
    this residual leakage is explicit.
27. Missing fragments: reconstruct C from k and re-encode.
28. Regeneration safety: C is authenticated ciphertext; verify old commitments
    and new record roots.
29. Reshared object: DEK itself; no G or wrapper master secret.
30. Distinctions: replacement, refresh, key rotation and full rotation are
    separate operations.
31. Periodic refresh: yes, on a policy schedule if DPSS quorum is healthy.
32. Mobile accumulation: independent epoch sharing plus secure erasure and
    per-epoch corruption bound.
33. Deletion: old D/subshares/grants/randomness and retired records.
34. Old guardian retention: cannot be prevented/proved in classical software.
35. Old share usefulness: only within its old epoch; k from that epoch remain
    dangerous.
36. Prior threshold compromise: rotation cannot undo it.
37. Atomicity: old ACTIVE through full PREPARE; QC activates only after all new
    records are durable.
38. States: separate Proposed/DelayPending/Preparing/Ready/Active/Draining/
    Retired/Aborted rotation states.
39. Current epoch: config-witness activation/read QCs.
40. Agreement: a narrow Byzantine register, not blockchain or public log.
41. Partitions: temporary views may differ, but only one successor QC can
    complete; ambiguous nodes fail closed.
42. Ambiguity: no release, DPSS finalization, activation or deletion.
43. Hard cancellation: request cancellation remains exact; a separate
    owner-signed rotation cancel can abort the transition.
44. Pending recovery: stays on its bound epoch.
45. Rotation during delay: old epoch drains it with unchanged not_before.
46. Request binding: exact ConfigRef discovered at request creation.
47. Delay bypass: rotation has the same or longer Begin -> Delay -> Release.
48. New recovery/leak path: DPSS coordinator gets A+C but not DEK; the dealer
    fallback is explicitly recovery-equivalent.
49. Denial of service: preparation aborts safely; signer/witness quorums remain
    availability trust boundaries.
50. Repeated metadata: fixed schedule/cover mitigates but cannot eliminate it.
51. Incentives: rotation failures alone are not automatically attributable.
52. Slashable evidence: only signed, independently verifiable equivocation,
    invalid proofs/bytes, or signed loss admissions—not timeouts.

---

# Research and dependency notes

The design is grounded in established lines of work rather than a new
resharing algorithm:

- Herzberg et al., [Proactive Secret Sharing](https://doi.org/10.1007/3-540-44750-4_27),
  introduces periodic share renewal for mobile adversaries.
- Zhou, Schneider and Van Renesse,
  [APSS](https://www.microsoft.com/en-us/research/publication/apss-proactive-secret-sharing-in-asynchronous-systems/),
  treats proactive refresh under asynchronous scheduling.
- Wong and Wing,
  [Verifiable Secret Redistribution for Archive Systems](https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf),
  shows why redistribution needs verification and private/broadcast channels.
- Baron et al.,
  [Communication-Optimal Proactive Secret Sharing for Dynamic Groups](https://eprint.iacr.org/2015/304),
  addresses changing committees and long-lived mobile compromise.
- Maram et al.,
  [CHURP](https://eprint.iacr.org/2019/017),
  provides a formally analyzed dynamic-committee proactive design and exposes
  the additional commitment/coordination assumptions such systems require.
- Nikov, Nikova and Preneel,
  [On Proactive Verifiable Secret Sharing Schemes](https://eudml.org/doc/11429),
  documents attacks on naive proactive constructions.
- Canetti et al.,
  [How to Protect Yourself Without Perfect Shredding](https://eprint.iacr.org/2008/291),
  explains why proactive sharing needs some erasure mechanism.
- Li et al.,
  [SUNDR](https://www.usenix.org/conference/osdi-04/secure-untrusted-data-repository-sundr),
  captures the fundamental freshness/fork limitation of untrusted storage.
- Shacham and Waters,
  [Compact Proofs of Retrievability](https://eprint.iacr.org/2008/073),
  distinguishes a formal extractable retrievability proof from a mere
  commitment or sample check.

Dependency reconnaissance on 2026-08-14:

- `blahaj 0.6.0` remains the repository-mandated dealer Shamir implementation
  and does not expose refresh/redistribution/VSS.
- `vsss-rs 6.0.1` exposes Shamir, Feldman and Pedersen primitives, including
  GF(256), but no complete dynamic proactive handoff/control protocol.
- `commonware-reshare 2026.7.0` is a maintained example over an epoched
  consensus log and BLS12-381 Feldman/Desmedt DKG. It is not a reusable
  arbitrary-byte DEK DPSS library and would replace the current crypto/control
  architecture.
- `secret_sharing_and_dkg 0.16.0` provides VSS/DKG building blocks but not the
  complete private-roster DPSS protocol required here.
- PoR crates found during search were not adopted; adding a SNARK/pairing PoR
  merely for health checks would expand assumptions and PQ/metadata surface.

These findings justify the implementation gate. A research paper plus field
primitives is not a maintained production DPSS implementation.

## Final non-claims

This implemented prototype does not claim:

- an external audit of this repository's exact FROST RTS + refresh-DKG
  integration;
- provable physical deletion;
- autonomous rotation with only the ordinary 5-of-8 recovery quorum in every
  fault model;
- zero metadata leakage from repeated handoffs;
- rollback safety while a fresh client is eclipsed from the witness quorum;
- healing after DEK/plaintext or an old complete threshold was compromised;
- that sampled Merkle retrieval is a formal proof of retrievability;
- full post-quantum security while Ed25519 or a classical DPSS construction is
  security-critical.
