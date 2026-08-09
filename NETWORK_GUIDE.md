# Guardian Protocol Network Runtime

This document explains the real multi-process network runtime from first
principles. It covers the actor model, Docker topology, HTTP APIs, end-to-end
envelopes, cryptographic objects, setup, recovery, delay enforcement,
cancellation, persistence, failure behavior, security boundaries, and the
remaining prototype limitations.

The authoritative protocol remains `MASTER_PROMPT.md`. This runtime does not
replace the deterministic simulator; it adds an actual socket-based execution
path for a live distributed demo.

## 1. What “real network” means here

The following are real in this runtime:

- relay, config-store, signer, and guardian nodes are independent operating
  system processes;
- Docker Compose runs each actor in a separate container with a separate
  persistent volume;
- the setup and recovery clients communicate with nodes using TCP and HTTP;
- mailbox request and response bodies are end-to-end encrypted with X-Wing and
  XChaCha20-Poly1305;
- every signer performs real Shamir-share encryption, Ed25519 approval/release
  signing, replay tracking, and persistent state updates;
- every guardian independently validates certificates, records Begin state,
  uses its local monotonic clock, verifies the pinned owner hard-cancel key,
  persists cancellation tombstones, and decides
  whether it may release;
- the recovery client reconstructs A, opens the private Recovery Descriptor,
  validates guardian material, reconstructs DEK and ciphertext, and decrypts
  the plaintext locally;
- an intentionally corrupt guardian produces a genuinely invalid contribution
  that the client rejects using its Merkle proof;
- a stopped container creates a real connection failure rather than a virtual
  “offline” flag.

The following are not production network features:

- the relay is one direct forwarding hop, not a production mixnet;
- STRONG-mode epochs, fixed cells, cover traffic, and dummy traffic remain in
  `gp-sim` only;
- Docker Compose enables automatic signer approval and a five-second demo
  delay; both are explicitly unsafe production substitutions;
- HTTP is used instead of TLS inside the Compose bridge. Protocol payloads are
  still end-to-end encrypted, but HTTP headers, timing, sizes, and endpoints
  remain visible;
- node JSON state is protected by filesystem permissions but is not encrypted
  at rest;
- network rotation is not exposed because the authoritative documents do not
  define a canonical threshold-authorized rotation message. Config Capsules
  are therefore immutable in this network MVP.

## 2. Components

### 2.1 Owner/setup client

The `gp-network setup` command is an ephemeral client. It:

1. discovers each signer's and guardian's static X-Wing transport public key;
2. generates random A, DEK, actor signing keys, config id, shares, fragments,
   opaque mailbox ids, and commitments;
3. encrypts the secret locally;
4. seals each node's provisioning record to that node;
5. registers random mailbox routes at the relay;
6. publishes the non-secret Config Capsule;
7. writes the privacy-sensitive Recovery Card;
8. writes a separate mode-0600 owner-control file containing the per-config
   cancellation private key and private guardian routes.

The setup client exits after distribution. A and DEK are held in zeroizing
buffers while setup is running and are not written to the Recovery Card.
The owner cancellation private key is never written to the Recovery Card or
sent to any node.

This owner-cancel design is protocol v2. Persistent node-state filenames carry
the protocol version, so old v1 state remains on disk but is not loaded as v2.
After upgrading, run setup again to create a v2 Recovery Card and owner-control
file. There is deliberately no migration that invents a cancellation private
key for an old configuration.

### 2.2 Relay

The relay owns this mapping:

```text
opaque mailbox id -> internal actor URL + actor transport public key
```

It exposes a public mailbox URL and forwards an opaque sealed body to the
registered actor. It cannot decrypt the body. It does learn:

- which opaque mailbox was contacted;
- the target actor process for that mailbox;
- request and response times;
- message sizes;
- network addresses adjacent to the relay.

It does not receive config id, request id, signer id, guardian index, plaintext
certificate, secret, A, DEK, share, or fragment as a plaintext HTTP field.

Mailbox registration requires the operational relay bearer token. Existing
mailboxes cannot be overwritten.

### 2.3 Config store

The config store serves public/pseudonymous Config Capsules by random config
id. Reads are public. Writes require the network administration bearer token.

For this MVP each config id is write-once. A higher version cannot overwrite
the existing value because a signed network rotation command has not been
specified. This fail-closed restriction prevents an unauthenticated or merely
token-bearing process from inventing a new protocol rotation behavior.

The config store never receives:

- plaintext secret;
- A or an A share;
- DEK or a DEK share;
- plaintext Recovery Descriptor;
- plaintext guardian roster.

### 2.4 Signer node

Each signer process has a persistent node identity and may host one or more
opaque signer mailboxes. Per mailbox it stores:

- its signer id;
- one Shamir share of A;
- an independent Ed25519 signing seed/public key;
- signer Merkle membership proof;
- pseudonymous policy and signer-set commitment;
- seen request ids and nonces.

For a recovery request it:

1. decrypts the mailbox envelope using its static X-Wing node key;
2. validates protocol/config version, expiry and recovery-recipient length;
3. rejects replayed request ids and nonces;
4. applies a persistent per-mailbox approval rate limit;
5. encrypts its A share to the fresh recovery recipient;
6. signs the canonical `SignerContribution` transcript;
7. seals the whole response to the recovery recipient;
8. persists replay state before returning.

In normal operation the signer must perform an external/social identity check.
The Compose demo sets `GP_AUTO_APPROVE=true`; without it the node refuses to
approve automatically.

### 2.5 Guardian node

Each guardian process has a persistent node identity and may host one or more
opaque guardian mailboxes. Each provisioned mailbox stores:

- one ciphertext fragment F_i;
- one A-wrapped DEK share E_i;
- guardian Merkle proof and local policy;
- independent guardian Ed25519 key;
- the per-config owner cancellation public key in its local policy;
- accepted Begin requests;
- seen nonces;
- permanent cancellation tombstones.

The guardian does not store plaintext secret, A, DEK, plaintext D_i, owner
identity, or the complete guardian roster.

The guardian uses two notions of time:

- Unix wall time validates request creation and expiry;
- Linux `/proc/uptime` provides monotonic seconds for the release delay.

The Linux boot id is persisted with each pending recovery. If the VM/container
kernel boot id changes during a delay, the guardian fails closed instead of
assuming that the delay elapsed. On non-Linux hosts the process id is used as
the fallback boot marker, so a process restart also fails closed.

### 2.6 Recovery client

`gp-network recover` starts with only the Recovery Card. It generates a fresh
one-time X-Wing recipient keypair and performs all plaintext reconstruction
inside that process.

It tolerates unavailable signers/guardians and rejects corrupt guardian
contributions until it has the configured number of valid responses.

`gp-network cancel` is a separate owner-side process. It reads the private
owner-control file and an exact observed RecoveryRequest, signs an owner-only
hard cancel, and requires `n - k + 1` distinct, signed guardian
acknowledgements. Each acknowledgement is encrypted to a fresh cancellation
response key and binds the exact cancel transcript. With the default eight
guardians and recovery threshold five, four valid acknowledgements are enough
to leave fewer than five uncancelled guardians.

A guardian persists both cancellation and successful-release state. It refuses
to sign a cancellation acknowledgement after it has released material for that
request. The hard cancel is intentionally not retroactive.

## 3. Docker topology

`compose.network.yml` starts:

```text
1 relay
1 config store
3 independent signer containers
8 independent guardian containers
1 ephemeral setup/recovery client image
```

Only two services are published to the host:

```text
127.0.0.1:9000 -> relay
127.0.0.1:9001 -> config store
```

Signer and guardian HTTP ports exist only on the private Compose bridge. Their
state lives in separate named volumes. `guardian-1` is intentionally configured
to corrupt its released fragment so replacement behavior is visible.

## 4. Quick start

Requirements:

- Docker Engine or Docker Desktop with Compose v2;
- enough space to compile the Rust image on the first run.

Run the complete live network demo:

```sh
make network-demo
```

This is equivalent to:

```sh
make network-up
make network-setup
make network-recover
```

Expected recovery output includes:

```text
signer approval via ...
guardian 1 rejected: invalid Merkle proof
guardian 2 contribution verified
...
reconstructed DEK, ciphertext, and plaintext on the recovery client
```

Files written under `demo-data/`:

```text
recovery-card.json
owner-control.json
recovered-secret.bin
```

Use another demo secret:

```sh
GP_DEMO_SECRET='my live demo secret' make network-setup
make network-recover
```

Run the actual cancellation race:

```sh
make network-cancel
```

The cancellation command:

1. creates a fresh configuration;
2. collects signer approvals;
3. sends Begin to guardians;
4. obtains a threshold-valid release certificate to model a hostile race;
5. signs the exact request with the setup-time owner cancellation private key;
6. stores owner-authorized cancellation tombstones on guardians;
7. waits until the real demo delay elapses;
8. presents the previously obtained release certificate;
9. requires an honest guardian to refuse it.

Stop containers without deleting state:

```sh
make network-down
```

To deliberately delete all Docker node state, run the explicit destructive
operation yourself:

```sh
docker compose -f compose.network.yml down --volumes
```

## 5. Running node types manually or on separate VMs

Build once:

```sh
cargo build --release -p gp-network
```

Relay:

```sh
GP_RELAY_ADMIN_TOKEN='replace-me' \
target/release/gp-network serve \
  --role relay --listen 0.0.0.0:8080 --data-dir ./state/relay
```

Config store:

```sh
GP_NETWORK_ADMIN_TOKEN='replace-me-too' \
target/release/gp-network serve \
  --role config-store --listen 0.0.0.0:8080 --data-dir ./state/config
```

Signer:

```sh
GP_NETWORK_ADMIN_TOKEN='replace-me-too' \
GP_AUTO_APPROVE=true \
target/release/gp-network serve \
  --role signer --listen 0.0.0.0:8080 --data-dir ./state/signer-1
```

Guardian with production delay enforcement:

```sh
GP_NETWORK_ADMIN_TOKEN='replace-me-too' \
target/release/gp-network serve \
  --role guardian --listen 0.0.0.0:8080 --data-dir ./state/guardian-1
```

Without `GP_ALLOW_INSECURE_DEMO_DELAY=true`, a guardian refuses provisioning
whose minimum delay is below 86,400 seconds.

The setup command writes two different bootstrap artifacts:

```text
recovery-card.json   public to read, privacy-sensitive, no private key
owner-control.json   mode 0600, contains the cancellation private key
```

To cancel an observed request from a separate owner process:

```sh
target/release/gp-network cancel \
  --request ./pending-recovery.json \
  --owner-control ./owner-control.json
```

The recovery process can export its exact public request transcript for a demo
or monitoring bridge with `--request-out ./pending-recovery.json`. A production
deployment still needs an authenticated owner-notification channel; the
recovery attacker cannot be expected to publish its own request voluntarily.

For VMs, expose signer and guardian node-info/provision endpoints only to the
setup administration network. Relay mailbox forwarding must still be able to
reach `/v1/mailbox/{opaque-id}`. Use firewall rules, TLS or a private overlay
network in addition to the protocol encryption.

## 6. HTTP API

### 6.1 Common endpoints

```text
GET /v1/health
GET /v1/node-info
```

`node-info` returns:

```json
{
  "protocol_version": 1,
  "node_id": "random-hex-id",
  "role": "signer",
  "transport_public_key": [0, 1, 2]
}
```

The transport public key is an X-Wing encapsulation key. The corresponding
decapsulation seed remains in that node's `identity.json`.

### 6.2 Provisioning

```text
POST /v1/provision
Authorization: Bearer <network-admin-token>
Content-Type: application/json
```

Body:

```json
{
  "sealed": {
    "kem_ciphertext": [],
    "payload": { "nonce": [], "ciphertext": [] }
  }
}
```

The inner payload is either a signer or guardian provisioning object. It is
sealed to the node's X-Wing key with associated-data context:

```text
gp/network-node-provision/v1 || node_id || role
```

The bearer token authenticates the administration operation. X-Wing provides
confidentiality to the intended node; it does not authenticate the sender by
itself.

### 6.3 Relay registration

```text
POST /v1/register
Authorization: Bearer <relay-admin-token>
```

Logical body:

```text
RouteRegistration {
    mailbox,
    target_url,
    transport_public_key
}
```

The relay refuses duplicate mailbox ids.

### 6.4 Relay mailbox

```text
GET  /v1/mailboxes/{opaque-id}/key
POST /v1/mailboxes/{opaque-id}
```

The GET returns the actor transport public key. POST accepts only a sealed
mailbox body and forwards it to:

```text
POST {target_url}/v1/mailbox/{opaque-id}
```

Request associated data:

```text
gp/network-mailbox-transport/v1 || mailbox || "request"
```

Response associated data:

```text
gp/network-mailbox-transport/v1 || mailbox || "response"
```

Requests are encrypted to the actor's static node key. Responses are encrypted
to the request's fresh recovery-recipient key. The relay can replace bytes but
cannot create a response that authenticates under the recipient's X-Wing/AEAD
context.

### 6.5 Config store

```text
GET /v1/configs/{config-id}
PUT /v1/configs/{config-id}
```

GET is public. PUT requires the network administration token. The random path
id must exactly equal the Config Capsule's embedded config id.

## 7. Setup communication sequence

```text
Owner          Signers/Guardians        Relay             Config Store
  |                    |                   |                    |
  |-- GET node-info -->|                   |                    |
  |<-- role + KEM pk --|                   |                    |
  |                    |                   |                    |
  | locally generate A, DEK, shares, encrypted payload, fragments
  | locally generate per-config owner cancellation signing key
  |                    |                   |                    |
  |-- sealed provision>|                   |                    |
  |<-- stored ack ------|                   |                    |
  |                    |                   |                    |
  |-- register opaque mailbox ------------>|                    |
  |<-- registered -------------------------|                    |
  |                    |                   |                    |
  |-- PUT public Config Capsule -------------------------------->|
  |<-- stored ---------------------------------------------------|
  |                    |                   |                    |
  | write Recovery Card and private owner-control file locally  |
```

### 7.1 Signer provisioning contents

```text
signer id
opaque mailbox URL
A share
independent Ed25519 seed/public key
Merkle membership proof
config/version and signer policy
empty replay state
```

### 7.2 Guardian provisioning contents

```text
guardian id
opaque mailbox URL and slot id
ciphertext fragment F_i
A-wrapped DEK share E_i
guardian Merkle proof
independent Ed25519 seed
minimal pseudonymous guardian policy
per-config owner cancellation public key
```

`GuardianPolicy.signer_count` is pinned in addition to the signer threshold and
Merkle root. Merkle membership verification needs the committed leaf count;
the simulator previously obtained it from privileged capsule state, while a
real guardian must be able to validate independently.

## 8. Recovery communication sequence

```text
Recovery       Relay       Signers       Config Store       Guardians
 Client
   |              |            |               |                |
   |-- GET Recovery Card locator ------------->|                |
   |<-- Config Capsule ------------------------|                |
   |                                                           |
   | generate fresh one-time X-Wing recipient                  |
   |                                                           |
   |-- sealed RecoveryRequest -->|-- forward -->|                |
   |<-- sealed SignerContribution|<-------------|                |
   |                                                           |
   | verify signatures/proofs; decrypt s A shares; reconstruct A
   | decrypt Recovery Descriptor and learn guardian mailboxes   |
   |                                                           |
   |-- sealed BeginCertificate --> relay ---------------------->|
   |<-- sealed BeginAccepted -----------------------------------|
   |                                                           |
   |         each guardian starts its own monotonic delay       |
   |                                                           |
   |-- sealed release request ->|--> signer                     |
   |<-- sealed ReleaseVote -----|                               |
   |                                                           |
   |-- sealed ReleaseCertificate ------------------------------>|
   |<-- sealed GuardianContribution ----------------------------|
   |                                                           |
   | verify and reject invalid material; collect k valid records
   | reconstruct DEK and ciphertext; decrypt plaintext locally  |
```

## 9. Exact message behavior

### RecoveryRequest

Created with fresh random request id, nonce and recipient key. Signatures bind
the entire canonical transcript, including config version, recipient, request
time and expiry.

### SignerContribution

The signer encrypts its A share directly to the recovery recipient with
request-and-signer-specific associated data. Its Ed25519 signature covers the
request and encrypted share. The recovery client verifies Merkle membership
before counting the contribution.

### BeginRecoveryCertificate

Contains the exact RecoveryRequest and threshold-valid SignerContributions.
Each guardian independently verifies all signer proofs and signatures. It then
persists request id, digest, nonce, boot id and monotonic `not_before`.

### OwnerCancelCertificate

Contains one Ed25519 owner signature under the per-config public key pinned
during setup. The signed transcript binds config id/version, request id/digest,
the hostile recovery recipient, nonce, reason, issue time, and a fresh response
recipient used only for encrypted guardian acknowledgements. Signers cannot
produce this certificate. A guardian stores a permanent request-id/digest
tombstone even if cancellation arrives before Begin. A conflicting digest
fails closed.

### ReleaseCertificate

Contains threshold-valid signer release votes bound to the same request,
recipient and nonce. It is not enough by itself: each guardian also requires a
locally stored Begin, elapsed monotonic delay, current boot marker, unexpired
request, current config and no cancellation tombstone.

### GuardianContribution

Contains the committed fragment, encrypted DEK share and Merkle proof. The
guardian signs the canonical contribution and the complete response is sealed
to the recovery recipient.

The client validates signature, request digest, guardian index, Merkle proof
and wrapped-share AEAD before counting it.

## 10. Actual delay enforcement

The network client really sleeps while each guardian independently compares
the current monotonic counter to its persisted `not_before` value. UI timers
are not involved.

Production guardian behavior:

```text
minimum_recovery_delay >= 86,400 seconds
```

Compose demo behavior:

```text
GP_ALLOW_INSECURE_DEMO_DELAY=true
minimum_recovery_delay = 5 seconds
```

The short delay is a visible demo-only configuration, not a claim that the
production policy changed.

## 11. Persistence and crash behavior

Each node writes JSON state atomically through a temporary file and rename.
Unix files are created with mode `0600`.

Persisted signer safety state:

- seen request ids;
- seen nonces;
- request digests.

Persisted guardian safety state:

- seen nonces;
- Begin request and digest;
- monotonic start/not-before;
- kernel boot id;
- cancellation tombstones.

If a guardian restarts under the same Linux kernel boot, `/proc/uptime` remains
monotonic and the pending delay can continue. If the kernel/VM reboots, the boot
id changes and release fails closed. An operator must perform a protocol-safe
new recovery attempt rather than manually editing state.

## 12. Failure demonstrations

### Corrupt guardian

`guardian-1` sets `GP_CORRUPT_CONTRIBUTION=true`. It flips one ciphertext byte,
signs the altered contribution, and returns it. The signature is valid for the
malicious bytes, but the bytes no longer match the setup Merkle commitment.
The client rejects guardian 1 and continues to guardian 2..n.

### Offline guardian

After setup, stop a guardian:

```sh
docker compose -f compose.network.yml stop guardian-2
make network-recover
```

The relay receives a real connection failure. The client treats it as an
unavailable contribution and continues until it has k valid responses.

### Offline signer

```sh
docker compose -f compose.network.yml stop signer-3
make network-recover
```

The default 2-of-3 threshold still succeeds.

### Insufficient threshold

Stopping two signers or four valid guardians causes recovery to fail. No code
path silently lowers the configured threshold.

### Guardian reboot during delay

Restarting the entire guardian VM/kernel changes its boot id. A later release
attempt fails closed. Restarting only the container on the same Docker host
normally preserves the Linux kernel boot id and monotonic uptime.

## 13. Observability for a live demo

List nodes:

```sh
docker compose -f compose.network.yml ps
```

Follow all network logs:

```sh
docker compose -f compose.network.yml logs -f
```

Inspect public health endpoints:

```sh
curl http://127.0.0.1:9000/v1/health
curl http://127.0.0.1:9001/v1/health
```

Inspect the Recovery Card:

```sh
jq . demo-data/recovery-card.json
```

It should contain config id, Config Capsule locator, signer mailbox URLs and
signer-set commitment. It must not contain a guardian field.

Inspect relay persistence inside its container only for debugging:

```sh
docker compose -f compose.network.yml exec relay \
  sh -c 'sed -n "1,80p" /data/relay-state.json'
```

That file demonstrates the relay's unavoidable knowledge: opaque mailbox to
next-hop mapping. It should not contain protocol requests or secrets.

## 14. Security boundaries and honest non-claims

This runtime demonstrates correct multi-process protocol behavior, not a
production deployment.

Important limitations:

1. Ed25519 signatures remain classical, so the system is post-quantum-skewed,
   not fully post-quantum.
2. The X-Wing crate used by this prototype has not been independently audited.
3. A threshold of compromised signers can authorize recovery and reconstruct A.
4. A threshold of compromised guardians can ignore their delay policy, though
   their stored DEK shares still require A.
5. The relay can drop all messages and prevent availability.
6. A global observer still sees endpoints, timing, volume and approximate
   message sizes.
7. One relay is not a mixnet and provides no strong anonymity claim.
8. Node state needs encrypted volumes, secret management, backups, OS hardening
   and access control before carrying valuable secrets.
9. The Compose administration tokens are demo defaults and must be replaced.
10. Automatic signer approval removes the required human verification step and
    exists only for unattended demonstration.
11. Release votes do not contain an independently verifiable guardian-delay
    timestamp. Guardians still enforce their own delay and cancellation state,
    but “fresh after delay” signer behavior depends on honest signer policy.
12. Signed config rotation is not defined in the authoritative message set, so
    this network MVP does not invent it.

## 15. Source map

```text
crates/gp-network/src/main.rs      CLI and node-role selection
crates/gp-network/src/server.rs    HTTP servers, persistence and node actions
crates/gp-network/src/client.rs    distributed setup/recovery orchestration
crates/gp-network/src/protocol.rs  shared setup and certificate validation
crates/gp-network/src/types.rs     network envelopes and persisted DTOs
crates/gp-core                     deterministic recovery/guardian machines
crates/gp-crypto                   all direct cryptographic library use
crates/gp-wire                     canonical transcripts and AEAD contexts
crates/gp-storage                  signer state and replay protection
compose.network.yml                13 long-lived actor containers + client
Dockerfile.network                 reproducible network-node image
```

## 16. Learning order

To understand the project from scratch:

1. Read `PROTOCOL.md` for the cryptographic object model.
2. Read `SECURITY.md` for threshold and cancellation assumptions.
3. Read `METADATA_RESISTANCE.md` for allowed privacy claims.
4. Follow setup in `protocol.rs::create_setup`.
5. Follow the setup HTTP calls in `client.rs::setup`.
6. Follow signer and guardian mailbox handlers in `server.rs`.
7. Follow `client.rs::recover` from Recovery Card to plaintext.
8. Read `gp-wire` transcripts to see exactly what each signature binds.
9. Read `gp-core::GuardianMachine` to see fail-closed delay and cancellation
   transitions independent of sockets and storage.
10. Run `make network-demo`, stop nodes, inspect logs, and repeat with
    `make network-cancel`.

That path separates three concerns cleanly:

```text
cryptographic protocol correctness
        +
deterministic state-machine correctness
        +
real process/network/storage execution
```

The visual simulator remains useful for deterministic replay and metadata
experiments. The network runtime is the place to demonstrate real node
boundaries, socket failures, persistent policy enforcement, and client-only
reconstruction.
