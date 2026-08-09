# Hackathon Demo Script

Target runtime: approximately four minutes.

## Preparation

- Use a fixed deterministic simulation seed.
- Default configuration:
  - 3 signers,
  - signer threshold 2,
  - 8 guardians,
  - guardian threshold 5,
  - minimum recovery delay represented as 24 hours but compressed to a few seconds in the simulator.
- Preload the GUI with actor positions so the graph is immediately readable.

## Leg 1 — Setup

1. Enter a secret or choose a small file.
2. Click `Protect & test recovery`.
3. Animate:

```text
secret
 -> DEK
 -> XChaCha20-Poly1305 ciphertext C
 -> Reed-Solomon fragments F_i
 -> guardians
```

4. Animate:

```text
A
 -> Shamir signer shares
 -> 3 signers
```

5. Animate:

```text
DEK
 -> Shamir DEK shares D_i
 -> encrypt D_i under A-derived per-guardian K_i
 -> E_i
 -> 8 guardians
```

6. Show that the Recovery Descriptor containing the guardian roster is encrypted under A.
7. Display the Recovery Card and label it:

> Non-confidential, privacy-sensitive recovery locator. It contains no secret key material and no guardian roster.

## Leg 2 — Recovery

1. Switch to a fresh recovery-device view with blank secret state.
2. Scan/import the Recovery Card.
3. Fetch the Config Capsule.
4. Generate a fresh recovery-recipient KEM keypair.
5. Send the RecoveryRequest to the three signers through the selected metadata mode.
6. Approve with two signers. Mark the third as offline.
7. Show:

```text
2 valid A shares -> reconstruct A
```

8. Decrypt the Recovery Descriptor and reveal guardian routing only inside the recovery-client visualization.
9. Send BeginRecoveryCertificate to guardians.
10. Start the compressed 24-hour countdown.
11. After the countdown, obtain the threshold ReleaseCertificate.
12. Guardians release valid contributions encrypted to the exact recovery recipient.
13. Show:

```text
A -> decrypt E_i -> D_i
k D_i -> DEK
k F_i -> C
DEK + C -> secret
```

14. Display the recovered secret only inside the recovery-client panel.

## Leg 3 — Malicious Guardian

1. Restart/replay from the same seed.
2. Toggle one guardian to `corrupt contribution` or `offline`.
3. Recovery receives a bad or missing response.
4. Show Merkle/AEAD verification failure.
5. Mark the response as rejected/erasure.
6. Fetch a replacement guardian contribution.
7. Complete recovery with k valid responses.

## Leg 4 — Cancellation

1. Replay to BeginRecoveryCertificate.
2. Let the delay almost expire.
3. Use the setup-time private owner cancellation key to sign the exact request.
4. Show the request state change to `Cancelled`.
5. Attempt to continue the release phase.
6. Honest guardians verify the pinned owner public key and refuse release.

## Leg 5 — Metadata Comparison

Compare the same seeded recovery in three modes.

### OFF

Show direct encrypted routes and explain there is no anonymity claim.

### BASIC

Show multi-hop routing, randomized delay, opaque mailbox ids, and no public event log.

### STRONG

Show:

- fixed-size/bucketed cells,
- epoch batching,
- dummy request traffic,
- dummy response traffic,
- rotating opaque mailbox ids,
- continuous configured-rate cover traffic,
- multi-hop paths,
- observer view with real/dummy classification hidden from the observer.

End with the accurate claim:

> The prototype keeps plaintext secret material off the network, does not publish the owner-to-guardian relationship, and demonstrates traffic-analysis resistance through simulated mixing and cover traffic. It does not claim perfect anonymity or a production mixnet.
