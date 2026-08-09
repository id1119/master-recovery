# Metadata Resistance

## Goal

Reduce the ability of a passive global observer or curious individual protocol participant to answer:

- who owns a secret,
- which guardians hold that owner's material,
- which deposit maps to which later recovery,
- when a particular user is performing a real recovery,
- which observed packets are real versus dummy.

The prototype does not attempt perfect size hiding or production-grade anonymous retrieval.

## 1. Metadata That Must Never Be Publicly Mapped

Do not create public mappings for:

```text
real owner identity -> config id
config id -> guardian roster
owner -> guardian roster
recovery request -> public plaintext event timeline
```

The guardian roster lives inside the Recovery Descriptor encrypted under A.

## 2. Recovery Card

The Recovery Card contains only:

- config id,
- Config Capsule locator,
- signer opaque mailbox handles,
- signer-set commitment.

It is non-confidential but privacy-sensitive.

It must not contain:

- guardian roster,
- guardian slot ids,
- A shares,
- DEK shares,
- plaintext secret,
- owner real-world identity.

## 3. Outer Transport Rules

Wherever possible, keep these values inside end-to-end encrypted payloads rather than outer headers:

- config id,
- request id,
- signer id,
- guardian index,
- recovery recipient,
- secret-related slot identifiers.

Outer routing should use only the opaque mailbox/routing material necessary for the current hop.
Opaque mailbox handles are random values and must not encode actor role,
guardian/signer index, config id, or another stable protocol identifier.

## 4. Metadata Modes

### OFF

Purpose: baseline demo only.

- direct encrypted delivery,
- no anonymity claim.

### BASIC

- multi-hop route,
- randomized forwarding delay,
- per-hop protection,
- opaque mailbox ids,
- rotating mailbox identifiers,
- no public plaintext event log,
- end-to-end encrypted protocol payload.

### STRONG

BASIC plus:

- fixed-size or size-bucketed cells,
- epoch batching,
- constant/configured-rate cover traffic,
- dummy requests when idle,
- dummy responses when idle,
- identical real/dummy outer packet format,
- rotating opaque mailbox ids by epoch,
- multi-hop paths for both requests and responses,
- real recovery packets mixed with unrelated/dummy traffic before endpoint delivery,
- observer-side timing/correlation visualization.

The simulator should maintain cover traffic among all visible participant classes so the presence of a packet alone is not equivalent to "a recovery is happening".

## 5. Strong-Mode Simulator Rule

The simulation kernel may know whether a packet is real or dummy for animation and scoring.

Protocol actors do not receive that bit.

The passive observer receives only the metadata visible on the observed link:

- timestamp,
- size bucket,
- previous/next hop visible on that link,
- outer packet type if the protocol exposes one.

Real/dummy classification must not be passed directly to the observer.

## 6. Unavoidable Leakage

Be explicit:

| Party | What it may inherently know |
|---|---|
| Owner | Its own secret/configuration |
| Recovery client | The recovered secret after successful reconstruction |
| Individual signer | It was asked to approve/cancel/release some pseudonymous recovery request |
| Individual guardian | One of its opaque stored records was accessed/released |
| Mix hop | Adjacent-hop timing/volume for packets it forwards |
| Passive global observer | Network timing/volume and approximate size buckets, but not plaintext contents |

A single signer should not learn the guardian roster merely by approving.

A single guardian should not learn the full guardian roster or owner identity.

A threshold of signers can reconstruct A and therefore can decrypt the Recovery Descriptor. That is part of the signer-threshold trust assumption.

## 7. Claims Allowed in the Demo

Good:

> The protocol hides plaintext content from network participants and avoids publishing the owner-to-guardian relationship. In strong simulation mode, fixed-size cells, multi-hop routing, rotating mailbox ids, batching, and continuous cover traffic make simple timing and sender/receiver correlation substantially harder.

Good:

> The prototype demonstrates metadata-resistant transport behavior; it does not claim a production anonymity network.

Bad:

> Nobody can know when any secret is retrieved.

Bad:

> Guardians cannot know that they are participating in a recovery.

Bad:

> Perfect anonymity.

## 8. GUI Requirements

The observer panel should compare OFF/BASIC/STRONG modes and show:

- number of real packets known only to the simulator,
- total observed packets,
- cover traffic volume,
- size buckets,
- timing distribution,
- path correlation visible to the observer,
- whether the observer can trivially isolate a real recovery flow.

The UI must also show a short "remaining leakage" explanation for each mode.
