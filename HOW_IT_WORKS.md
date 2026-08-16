# How Master Recovery works

This guide follows one recovery configuration from setup through guardian
replacement. It assumes technical experience but no background in threshold
cryptography.

For exact fields and validation rules, read [PROTOCOL.md](PROTOCOL.md). For the
failure model, read [SECURITY.md](SECURITY.md).

## The example

Alice wants to protect a wallet recovery secret. She chooses:

- three signers, with any two required to authorize recovery;
- eight guardians, with any five required to supply custody material;
- a 24-hour recovery delay;
- four witnesses for guardian-epoch freshness, where three form a quorum.

The signers may be people or services that can perform an identity check. The
guardians are storage operators. They do different jobs and receive different
material.

```text
Authorization                 Custody

S1  S2  S3                    G1 G2 G3 G4 G5 G6 G7 G8
 \  |  /                       \       any 5       /
  any 2                         encrypted material
      \                         /
       \                       /
        fresh recovery device
```

## What each actor holds

| Actor | Holds or learns | Does not hold |
|---|---|---|
| Alice during setup | Plaintext, Recovery Card, private owner-control file | Nothing is missing during setup; this is the point where the configuration is created |
| Signer | One share of authorization key `A`, its signing key, and replay state | Guardian roster, DEK, ciphertext fragments, plaintext |
| Guardian | One encrypted DEK share, one ciphertext fragment, policy, and proofs | `A`, plaintext DEK share at rest, full roster, plaintext |
| Witness | Public capsule hashes, epoch order, and signed activation state | Private roster, shares, DEK, plaintext |
| Relay | Opaque mailbox route, adjacent endpoints, timing, and size | Decrypted protocol messages |
| Recovery client | Recovery Card at start; plaintext only after success | Any long-lived setup secret before recovery begins |

The owner-control file is not another recovery key. It gives Alice the power
to cancel a request or rotation. It cannot approve recovery or decrypt the
payload.

## Setup

Alice starts with the plaintext only on her setup device.

1. The client generates two unrelated random keys. `A` controls access to the
   private recovery configuration. `DEK` encrypts the wallet secret.
2. The client splits `A` into three signer shares. Any two can reconstruct it.
3. The client encrypts the wallet secret with `DEK`.
4. It Reed-Solomon encodes the ciphertext into eight fragments. Any five valid
   fragments can reconstruct the ciphertext.
5. It creates eight DEK shares. Any five can reconstruct `DEK`.
6. Each DEK share is encrypted under a different key derived from `A` and that
   guardian's exact configuration and index.
7. Each guardian receives one encrypted DEK share, one ciphertext fragment,
   and integrity and policy data.
8. The private Recovery Descriptor records how to contact the guardians. It is
   encrypted under a key derived from `A`.
9. A public, pseudonymous Config Capsule commits to the configuration without
   publishing the guardian roster.
10. Alice saves the Recovery Card and the separate private owner-control file.

At the end of setup, no signer or guardian has the plaintext. A signer has
authorization material but no custody material. A guardian has custody
material whose DEK share is still encrypted under `A`.

## Why the Recovery Card is safe to copy but not safe to publish

The Recovery Card tells a new device where to begin. It contains configuration
locators, opaque signer mailboxes, relay addresses, public commitments, the
owner cancellation public key, and protocol-v3 witness pins.

It does not contain a seed phrase, decryption key, `A` share, DEK share,
plaintext, or guardian roster. Stealing it does not complete recovery.

The card is still privacy-sensitive. It identifies one pseudonymous recovery
configuration and some of the infrastructure used to reach it. Alice can keep
copies in places where a locator is acceptable, but publishing it creates
unnecessary metadata and request-spam exposure.

## Recovery on a new device

Years later, Alice has lost her wallet devices. She scans the Recovery Card on
a fresh device.

### 1. Create an exact recipient

The device creates a one-time X-Wing recipient keypair and a new request id and
nonce. Every approval and contribution binds to this request and recipient.
Material sent for another request or device will not validate.

### 2. Ask the signers

Each signer performs its external identity check. In this example, S1 and S3
approve. Each returns its `A` share encrypted to the fresh device and signs the
exact request transcript.

The device verifies both signer identities, membership proofs, signatures,
request fields, and recipient binding. It reconstructs `A` only after two valid
contributions arrive.

### 3. Open the private descriptor

With `A`, the device decrypts the Recovery Descriptor and learns the guardian
mailboxes and opaque slots. This is why the public Recovery Card does not need
to expose the guardian roster.

A threshold of signers can also reconstruct `A` and open this descriptor. That
is a stated trust boundary, not a hidden privacy guarantee.

### 4. Begin the guardian delay

The device sends a Begin certificate containing the signer approvals to the
guardians. Each honest guardian verifies it and records a local monotonic
`not_before` time 24 hours in the future.

The delay is policy enforced by guardian software. It is not a cryptographic
timelock. A compromised guardian can ignore its own policy, but an attacker
still needs enough material to cross the relevant thresholds.

### 5. Release after the delay

After 24 hours, the device asks the signers for fresh Release votes over the
same request. Two valid votes form the Release certificate.

An honest guardian releases only if its delay elapsed, the request is current,
the Release certificate is valid, and it has not recorded a valid owner
cancellation.

### 6. Reconstruct locally

The recovery client collects five valid guardian contributions. For each one,
it verifies the guardian signature, committed record, Merkle proof, exact
request, recipient, configuration, guardian index, and fragment index.

It derives the five guardian wrapping keys from `A`, opens the five DEK shares,
reconstructs `DEK`, reconstructs the ciphertext from five fragments, and
decrypts the wallet secret. Temporary secret buffers are zeroized where the
libraries support it.

The relay, signers, guardians, config store, and witnesses never perform this
final plaintext reconstruction.

## Cancellation during the delay

Suppose Alice sees an unexpected recovery notification after Begin.

Alice's owner device signs a cancellation certificate for that exact request.
Each honest guardian stores a permanent tombstone before acknowledging it. In
an 8-guardian, 5-of-8 configuration, Alice needs acknowledgements from at least
four distinct guardians. That leaves fewer than five available to satisfy the
recovery threshold.

Cancellation has limits:

- it needs the private owner-control key;
- malicious guardians may break policy after acknowledging;
- it cannot recall contributions already released to a recovery client;
- losing the owner key removes cancellation but does not reveal the secret;
- compromising the owner key permits denial of service, not recovery.

## One guardian fails

If G4 is offline during normal recovery, the client can use another five
guardians. Thresholds provide fault tolerance as long as enough valid actors
remain.

For a long-lived configuration, leaving failed guardians in the roster is not
enough. Protocol v3 can replace G4 with G9:

```text
Epoch 1: G1 G2 G3 G4 G5 G6 G7 G8
Epoch 2: G1 G2 G3 G9 G5 G6 G7 G8
```

## Guardian rotation

A rotation follows its own signer-authorized Begin, Delay, Release, and
Activate flow.

1. The coordinator reads a fresh witness quorum and proposes the exact direct
   successor to the active epoch.
2. A signer threshold authorizes the plan and releases `A` to the fresh
   rotation recipient.
3. A threshold of old guardians contributes to FROST repair, so G4 does not
   need to cooperate in its own replacement.
4. The complete successor roster runs FROST refresh-DKG. Every guardian ends
   with one independently refreshed share of the same `DEK`.
5. The coordinator reconstructs only the encrypted ciphertext from valid old
   fragments and re-encodes it. A stable Merkle commitment proves that each
   successor received the correct fragment.
6. Every successor keeps its wrapped DEK share and full record locally. The
   coordinator sees only commitment leaves, even though it knows `A` and the
   wrapping keys.
7. All successor records must be durably `PREPARED`. Their acknowledgements
   sign the same material root.
8. Signers authorize the exact successor capsule. Three of four witnesses
   durably accept that one direct child and produce the activation quorum.
9. The new epoch becomes active atomically. The old epoch serves only requests
   that began before activation, then retires after its drain deadline.

The payload is never decrypted during this path. The ordinary coordinator does
not receive plaintext DEK shares or enough wrapped-share ciphertext to open a
threshold.

## Historical shares and epochs

A guardian share is valid only inside its exact `ConfigRef`, which includes the
configuration id, payload generation, authorization epoch, guardian epoch, and
an unpredictable epoch binding.

Refresh creates a new sharing of the same `DEK`. Old and new shares are not an
approved combined set. Recovery obtains the active capsule from a fresh
witness quorum, checks every contribution against that epoch, and rejects
mixed labels before calling FROST reconstruction.

This protects the protocol entry point from accidental or adversarial mixing.
The stronger proactive claim still assumes secure erasure and that an attacker
never obtains a complete valid threshold within one epoch. Rotation cannot
heal a `DEK` that was already reconstructed or plaintext that was already
stolen.

## What the example leaves out

The live relay is a direct forwarding hop. OFF, BASIC, and STRONG traffic
privacy modes are simulator experiments, not a deployed mixnet. The Docker
demo shortens the delay and auto-approves signer requests. The project has not
received a professional security audit and is not production ready.

Continue with:

- [PROTOCOL.md](PROTOCOL.md) for exact messages and reconstruction steps;
- [SECURITY.md](SECURITY.md) for compromise and availability cases;
- [GUARDIAN_ROTATION.md](GUARDIAN_ROTATION.md) for the full epoch protocol;
- [NETWORK_GUIDE.md](NETWORK_GUIDE.md) for processes, APIs, and commands.
