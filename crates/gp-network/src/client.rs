use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use gp_crypto::{RecipientKeyPair, seal_to_recipient, zeroize_id};
use gp_types::{
    BeginRecoveryCertificate, ConfigCapsule, RecoveryCard, RecoveryRequest, ReleaseCertificate,
    SetupPolicy,
};

use crate::{
    protocol::{
        create_setup, make_owner_cancel_certificate, open_descriptor, random_id, random_nonce,
        reconstruct_a, reconstruct_payload, validate_capsule, validate_guardian_contribution,
        validate_owner_cancel_ack, wall_now,
    },
    types::{
        MailboxRequest, MailboxResponse, NetworkDemoResult, NodeInfo, OwnerCancelResult,
        OwnerControlFile, ProvisionPayload, RouteRegistration, SealedMailboxBody,
    },
};

pub struct SetupOptions {
    pub secret: Vec<u8>,
    pub config_stores: Vec<String>,
    pub relays: Vec<String>,
    pub relay_token: String,
    pub admin_token: String,
    pub signers: Vec<String>,
    pub guardians: Vec<String>,
    pub signer_threshold: u16,
    pub guardian_threshold: u16,
    pub delay_secs: u64,
    pub card_path: String,
    pub owner_control_path: String,
}

pub struct RecoverOptions {
    pub card_path: String,
    pub output_path: Option<String>,
    pub request_out_path: Option<String>,
    pub cancel_before_release: bool,
    pub owner_control_path: String,
}

pub struct CancelOptions {
    pub request_path: String,
    pub owner_control_path: String,
}

pub async fn setup(options: SetupOptions) -> Result<RecoveryCard> {
    let client = reqwest::Client::new();
    if options.signers.is_empty()
        || options.guardians.is_empty()
        || options.relays.is_empty()
        || options.config_stores.is_empty()
    {
        bail!("at least one signer, guardian, relay, and config store is required");
    }
    let relay_bases = options
        .relays
        .iter()
        .map(|relay| relay.trim_end_matches('/').to_string())
        .collect::<Vec<_>>();
    let signer_count = u16::try_from(options.signers.len())?;
    let guardian_count = u16::try_from(options.guardians.len())?;
    let signer_mailboxes = (0..options.signers.len())
        .map(|_| mailbox_url(&relay_bases[0]))
        .collect::<Vec<_>>();
    let guardian_mailboxes = (0..options.guardians.len())
        .map(|_| mailbox_url(&relay_bases[0]))
        .collect::<Vec<_>>();
    let policy = SetupPolicy {
        signer_count,
        signer_threshold: options.signer_threshold,
        guardian_count,
        guardian_threshold: options.guardian_threshold,
        minimum_recovery_delay: options.delay_secs,
    };
    let bundle = create_setup(
        &options.secret,
        &policy,
        signer_mailboxes,
        guardian_mailboxes,
        &options.config_stores,
        &relay_bases,
    )?;
    let mut owner_control = OwnerControlFile {
        protocol_version: bundle.capsule.protocol_version,
        config_id: bundle.capsule.config_id,
        config_version: bundle.capsule.config_version,
        owner_cancel_signing_seed: bundle
            .owner_cancel_signing_seed
            .as_slice()
            .try_into()
            .context("invalid owner cancellation signing seed")?,
        owner_cancel_public_key: bundle.capsule.owner_cancel_public_key,
        guardian_count: bundle.capsule.guardian_count,
        guardian_threshold: bundle.capsule.guardian_threshold,
        guardian_routes: bundle.owner_guardian_routes.clone(),
        relay_bases: relay_bases.clone(),
    };

    println!("SETUP config={}", hex::encode(bundle.capsule.config_id));
    for ((target, signer), mailbox) in options
        .signers
        .iter()
        .zip(bundle.signers)
        .zip(bundle.card.signer_mailboxes.iter())
    {
        provision_actor(
            &client,
            target,
            "signer",
            ProvisionPayload::Signer(signer),
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(&client, relay, &options.relay_token, mailbox, target).await?;
        }
        println!(
            "  provisioned signer mailbox {} on {} relay(s)",
            short_mailbox(mailbox),
            relay_bases.len()
        );
    }
    for (target, guardian) in options.guardians.iter().zip(bundle.guardians) {
        let mailbox = guardian.mailbox.clone();
        provision_actor(
            &client,
            target,
            "guardian",
            ProvisionPayload::Guardian(guardian),
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(&client, relay, &options.relay_token, &mailbox, target).await?;
        }
        println!(
            "  provisioned guardian mailbox {} on {} relay(s)",
            short_mailbox(&mailbox),
            relay_bases.len()
        );
    }

    let config_id = hex::encode(bundle.capsule.config_id);
    for store in &options.config_stores {
        let response = client
            .put(format!(
                "{}/v1/configs/{config_id}",
                store.trim_end_matches('/')
            ))
            .bearer_auth(&options.admin_token)
            .json(&bundle.capsule)
            .send()
            .await?;
        ensure_success(response, "publish Config Capsule").await?;
    }
    write_private_json(Path::new(&options.card_path), &bundle.card)?;
    write_private_json(Path::new(&options.owner_control_path), &owner_control)?;
    zeroize_id(&mut owner_control.owner_cancel_signing_seed);
    println!(
        "  published Config Capsule to {} config store(s) and wrote {} plus private owner control {}",
        options.config_stores.len(),
        options.card_path,
        options.owner_control_path
    );
    Ok(bundle.card)
}

async fn provision_actor(
    client: &reqwest::Client,
    target: &str,
    expected_role: &str,
    payload: ProvisionPayload,
    admin_token: &str,
) -> Result<()> {
    let info = client
        .get(format!("{}/v1/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    if info.protocol_version != gp_types::PROTOCOL_VERSION || info.role != expected_role {
        bail!(
            "node {target} has role {}, expected {expected_role}",
            info.role
        );
    }
    let bytes = serde_json::to_vec(&payload)?;
    let sealed = seal_to_recipient(
        &info.transport_public_key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::node_provision_context(&info.node_id, expected_role)?,
    )?;
    let response = client
        .post(format!("{}/v1/provision", target.trim_end_matches('/')))
        .bearer_auth(admin_token)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    ensure_success(response, "provision actor").await?;
    Ok(())
}

async fn register_route(
    client: &reqwest::Client,
    relay: &str,
    token: &str,
    mailbox_url: &str,
    target: &str,
) -> Result<()> {
    let info = client
        .get(format!("{}/v1/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    let registration = RouteRegistration {
        mailbox: mailbox_id(mailbox_url)?,
        target_url: target.trim_end_matches('/').into(),
        transport_public_key: info.transport_public_key,
    };
    let response = client
        .post(format!("{}/v1/register", relay.trim_end_matches('/')))
        .bearer_auth(token)
        .json(&registration)
        .send()
        .await?;
    ensure_success(response, "register relay mailbox").await?;
    Ok(())
}

pub async fn recover(options: RecoverOptions) -> Result<NetworkDemoResult> {
    let client = reqwest::Client::new();
    let card: RecoveryCard = serde_json::from_slice(&fs::read(&options.card_path)?)?;
    let capsule_locators = card.all_capsule_locators();
    if capsule_locators.is_empty() {
        bail!("Recovery Card contains no config store locators");
    }
    let mut last_store_error: Option<anyhow::Error> = None;
    let mut capsule = None;
    for locator in capsule_locators {
        match client.get(locator).send().await {
            Ok(response) => {
                let status = response.status();
                match response.error_for_status() {
                    Ok(response) => match response.json::<ConfigCapsule>().await {
                        Ok(value) => match validate_capsule(&card, &value) {
                            Ok(()) => {
                                capsule = Some(value);
                                println!("  fetched Config Capsule from {locator}");
                                break;
                            }
                            Err(error) => {
                                last_store_error = Some(error.context(format!(
                                    "config store {locator} returned a capsule that does not match the Recovery Card"
                                )))
                            }
                        },
                        Err(error) => last_store_error = Some(error.into()),
                    },
                    Err(error) => {
                        last_store_error = Some(
                            anyhow::Error::new(error)
                                .context(format!("config store {locator} responded with {status}")),
                        )
                    }
                }
            }
            Err(error) => {
                last_store_error = Some(
                    anyhow::Error::new(error)
                        .context(format!("config store {locator} unreachable")),
                )
            }
        }
    }
    let capsule = capsule.ok_or_else(|| {
        let detail = last_store_error
            .as_ref()
            .map_or_else(|| "unknown".to_string(), |error| error.to_string());
        anyhow::anyhow!("no config store responded: {detail}")
    })?;
    let recipient = RecipientKeyPair::from_seed(random_id());
    let now = wall_now()?;
    let request = RecoveryRequest {
        protocol_version: gp_types::PROTOCOL_VERSION,
        crypto_suite: capsule.crypto_suite,
        config_id: capsule.config_id,
        config_version: capsule.config_version,
        request_id: random_id(),
        recovery_recipient_key: recipient.public_key().to_vec(),
        requested_at: now,
        nonce: random_id(),
        expiry: now.saturating_add(capsule.max_request_lifetime),
    };
    if let Some(path) = &options.request_out_path {
        write_private_json(Path::new(path), &request)?;
        println!("  wrote public recovery transcript to {path} for owner monitoring");
    }
    println!("RECOVERY request={}", hex::encode(request.request_id));

    let mut signer_contributions = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_mailbox_mirrored(
            &client,
            mailbox,
            &card.relay_bases,
            &MailboxRequest::SignerApprove {
                request: request.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::SignerContribution(value)) => {
                signer_contributions.push(value);
                println!("  signer approval via {}", short_mailbox(mailbox));
            }
            Ok(_) => println!(
                "  signer {} returned the wrong response",
                short_mailbox(mailbox)
            ),
            Err(error) => println!("  signer {} unavailable: {error}", short_mailbox(mailbox)),
        }
        if signer_contributions.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if signer_contributions.len() < usize::from(capsule.signer_threshold) {
        bail!("signer approval threshold was not reached");
    }
    let begin = BeginRecoveryCertificate {
        request: request.clone(),
        signer_contributions,
    };
    let authorization_key = reconstruct_a(&begin, &capsule, &recipient, wall_now()?)?;
    let descriptor = open_descriptor(&capsule, &authorization_key)?;
    println!("  reconstructed A and opened private guardian descriptor locally");

    let mut begin_count = 0_usize;
    for route in &descriptor.guardians {
        match send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &MailboxRequest::GuardianBegin {
                certificate: begin.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::BeginAccepted { .. }) => {
                begin_count += 1;
                println!("  guardian {} accepted Begin", route.guardian_index);
            }
            Ok(_) => println!(
                "  guardian {} returned the wrong response",
                route.guardian_index
            ),
            Err(error) => println!("  guardian {} unavailable: {error}", route.guardian_index),
        }
    }
    if begin_count < usize::from(capsule.guardian_threshold) {
        bail!("not enough guardians accepted Begin");
    }

    if options.cancel_before_release {
        // Capture a threshold-valid release certificate before the owner's hard cancel to model
        // a hostile recovery client racing an older certificate against the owner tombstone.
        let mut pre_cancel_release_votes = Vec::new();
        for mailbox in &card.signer_mailboxes {
            if let Ok(MailboxResponse::ReleaseVote(vote)) = send_mailbox_mirrored(
                &client,
                mailbox,
                &card.relay_bases,
                &MailboxRequest::SignerRelease {
                    request: request.clone(),
                },
                &recipient,
            )
            .await
            {
                pre_cancel_release_votes.push(vote);
            }
            if pre_cancel_release_votes.len() >= usize::from(capsule.signer_threshold) {
                break;
            }
        }
        if pre_cancel_release_votes.len() < usize::from(capsule.signer_threshold) {
            bail!("could not construct the cancellation-race release certificate");
        }
        let raced_release = ReleaseCertificate {
            votes: pre_cancel_release_votes,
        };
        let mut owner_control: OwnerControlFile =
            serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
        if owner_control.protocol_version != gp_types::PROTOCOL_VERSION
            || owner_control.config_id != request.config_id
            || owner_control.config_version != request.config_version
            || owner_control.owner_cancel_public_key != capsule.owner_cancel_public_key
            || owner_control.guardian_count != capsule.guardian_count
            || owner_control.guardian_threshold != capsule.guardian_threshold
            || owner_control.guardian_routes != descriptor.guardians
            || owner_control.relay_bases != card.relay_bases
        {
            bail!("owner control file does not match this recovery configuration");
        }
        let cancel_recipient = RecipientKeyPair::from_seed(random_id());
        let certificate_result = make_owner_cancel_certificate(
            &request,
            owner_control.owner_cancel_signing_seed,
            cancel_recipient.public_key().to_vec(),
            1,
            wall_now()?,
        );
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        let certificate = certificate_result?;
        let mut cancelled_guardians = BTreeSet::new();
        for route in &descriptor.guardians {
            if let Ok(MailboxResponse::CancellationAccepted(ack)) = send_mailbox_mirrored(
                &client,
                &route.mailbox,
                &card.relay_bases,
                &MailboxRequest::GuardianCancel {
                    request: request.clone(),
                    certificate: Box::new(certificate.clone()),
                },
                &cancel_recipient,
            )
            .await
                && validate_owner_cancel_ack(&ack, &certificate, &request, route).is_ok()
            {
                cancelled_guardians.insert(ack.guardian_index);
            }
        }
        let required_acks = required_cancel_acks(
            usize::from(capsule.guardian_count),
            usize::from(capsule.guardian_threshold),
        )?;
        if cancelled_guardians.len() < required_acks {
            bail!("cancellation did not reach enough guardians");
        }
        println!(
            "  owner hard-cancel tombstone stored by {} guardians",
            cancelled_guardians.len()
        );
        tokio::time::sleep(Duration::from_secs(
            capsule.minimum_recovery_delay.saturating_add(1),
        ))
        .await;
        let mut observed_refusal = false;
        for route in &descriptor.guardians {
            match send_mailbox_mirrored(
                &client,
                &route.mailbox,
                &card.relay_bases,
                &MailboxRequest::GuardianRelease {
                    request: request.clone(),
                    certificate: raced_release.clone(),
                },
                &recipient,
            )
            .await
            {
                Ok(MailboxResponse::GuardianContribution(_)) => {
                    bail!("cancelled guardian released material")
                }
                Ok(MailboxResponse::ReleaseRefused { reason }) if reason == "cancelled" => {
                    observed_refusal = true;
                    println!(
                        "  guardian {} refused the raced release certificate",
                        route.guardian_index
                    );
                    break;
                }
                Ok(_) | Err(_) => {}
            }
        }
        if !observed_refusal {
            bail!("no guardian produced an authenticated cancellation refusal");
        }
        return Ok(NetworkDemoResult {
            config_id: hex::encode(capsule.config_id),
            request_id: hex::encode(request.request_id),
            recovered_secret: None,
            signer_contributions: usize::from(capsule.signer_threshold),
            guardian_contributions: 0,
            rejected_guardians: vec![],
            cancelled: true,
        });
    }

    println!(
        "  waiting {} real seconds for guardian-local monotonic delays",
        capsule.minimum_recovery_delay
    );
    tokio::time::sleep(Duration::from_secs(
        capsule.minimum_recovery_delay.saturating_add(1),
    ))
    .await;

    let mut release_votes = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_mailbox_mirrored(
            &client,
            mailbox,
            &card.relay_bases,
            &MailboxRequest::SignerRelease {
                request: request.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::ReleaseVote(vote)) => release_votes.push(vote),
            Ok(_) => {}
            Err(error) => println!("  release signer unavailable: {error}"),
        }
        if release_votes.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if release_votes.len() < usize::from(capsule.signer_threshold) {
        bail!("release vote threshold was not reached");
    }
    let release = ReleaseCertificate {
        votes: release_votes,
    };

    let mut fragments = Vec::new();
    let mut dek_shares = Vec::new();
    let mut rejected = Vec::new();
    for route in &descriptor.guardians {
        match send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &MailboxRequest::GuardianRelease {
                request: request.clone(),
                certificate: release.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::GuardianContribution(contribution)) => {
                match validate_guardian_contribution(
                    &contribution,
                    route,
                    &descriptor,
                    &request,
                    &authorization_key,
                ) {
                    Ok(share) => {
                        fragments.push((
                            contribution.guardian_index,
                            contribution.ciphertext_fragment,
                        ));
                        dek_shares.push(share);
                        println!("  guardian {} contribution verified", route.guardian_index);
                    }
                    Err(error) => {
                        rejected.push(route.guardian_index);
                        println!("  guardian {} rejected: {error}", route.guardian_index);
                    }
                }
            }
            Ok(_) => rejected.push(route.guardian_index),
            Err(error) => {
                rejected.push(route.guardian_index);
                println!("  guardian {} unavailable: {error}", route.guardian_index);
            }
        }
        if fragments.len() >= usize::from(capsule.guardian_threshold) {
            break;
        }
    }
    if fragments.len() < usize::from(capsule.guardian_threshold) {
        bail!("guardian threshold was not reached");
    }
    let plaintext = reconstruct_payload(&capsule, &descriptor, &fragments, &dek_shares)?;
    let recovered = String::from_utf8_lossy(&plaintext).into_owned();
    if let Some(path) = &options.output_path {
        fs::write(path, &*plaintext)?;
    }
    println!("  reconstructed DEK, ciphertext, and plaintext on the recovery client");
    Ok(NetworkDemoResult {
        config_id: hex::encode(capsule.config_id),
        request_id: hex::encode(request.request_id),
        recovered_secret: Some(recovered),
        signer_contributions: usize::from(capsule.signer_threshold),
        guardian_contributions: fragments.len(),
        rejected_guardians: rejected,
        cancelled: false,
    })
}

pub async fn cancel(options: CancelOptions) -> Result<OwnerCancelResult> {
    let client = reqwest::Client::new();
    let request: RecoveryRequest = serde_json::from_slice(&fs::read(&options.request_path)?)?;
    let mut owner_control: OwnerControlFile =
        serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
    let now = wall_now()?;
    if owner_control.protocol_version != gp_types::PROTOCOL_VERSION
        || request.protocol_version != gp_types::PROTOCOL_VERSION
        || owner_control.config_id != request.config_id
        || owner_control.config_version != request.config_version
        || request.requested_at > now
        || request.expiry <= now
        || usize::from(owner_control.guardian_count) != owner_control.guardian_routes.len()
        || owner_control.guardian_threshold == 0
        || owner_control.guardian_threshold > owner_control.guardian_count
    {
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        bail!("owner control file and recovery request do not form a valid active configuration");
    }
    let expected_public = gp_crypto::verifying_key_bytes(&gp_crypto::signing_key(
        owner_control.owner_cancel_signing_seed,
    ));
    if expected_public != owner_control.owner_cancel_public_key {
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        bail!("owner control private key does not match its pinned public key");
    }
    let cancel_recipient = RecipientKeyPair::from_seed(random_id());
    let certificate_result = make_owner_cancel_certificate(
        &request,
        owner_control.owner_cancel_signing_seed,
        cancel_recipient.public_key().to_vec(),
        1,
        now,
    );
    zeroize_id(&mut owner_control.owner_cancel_signing_seed);
    let certificate = certificate_result?;
    let mut acknowledgements = BTreeSet::new();
    for route in &owner_control.guardian_routes {
        if let Ok(MailboxResponse::CancellationAccepted(ack)) = send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &owner_control.relay_bases,
            &MailboxRequest::GuardianCancel {
                request: request.clone(),
                certificate: Box::new(certificate.clone()),
            },
            &cancel_recipient,
        )
        .await
            && validate_owner_cancel_ack(&ack, &certificate, &request, route).is_ok()
        {
            acknowledgements.insert(ack.guardian_index);
        }
    }
    let required_acks = required_cancel_acks(
        usize::from(owner_control.guardian_count),
        usize::from(owner_control.guardian_threshold),
    )?;
    if acknowledgements.len() < required_acks {
        bail!(
            "owner hard-cancel reached {} guardians, fewer than the required {required_acks}",
            acknowledgements.len()
        );
    }
    Ok(OwnerCancelResult {
        config_id: hex::encode(request.config_id),
        request_id: hex::encode(request.request_id),
        guardian_acknowledgements: acknowledgements.len(),
        permanently_cancelled: true,
    })
}

fn required_cancel_acks(total_guardians: usize, recovery_threshold: usize) -> Result<usize> {
    if recovery_threshold == 0 || recovery_threshold > total_guardians {
        bail!("invalid guardian threshold in owner control state");
    }
    Ok(total_guardians - recovery_threshold + 1)
}

async fn send_mailbox_mirrored(
    client: &reqwest::Client,
    mailbox: &str,
    relays: &[String],
    action: &MailboxRequest,
    recipient: &RecipientKeyPair,
) -> Result<MailboxResponse> {
    let mut last_error: Option<anyhow::Error> = None;
    let mut tried = 0_usize;
    for candidate in mailbox_replicas(mailbox, relays) {
        tried += 1;
        match send_mailbox(client, &candidate, action, recipient).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.context(format!(
            "mailbox {} unreachable via {tried} relay replica(s)",
            short_mailbox(mailbox)
        ))),
        None => bail!("no relay replicas configured"),
    }
}

fn mailbox_replicas(mailbox: &str, relay_bases: &[String]) -> Vec<String> {
    let mut replicas = vec![mailbox.to_string()];
    let Ok(id) = mailbox_id(mailbox) else {
        return replicas;
    };
    for base in relay_bases {
        let candidate = format!("{}/v1/mailboxes/{}", base.trim_end_matches('/'), id);
        if !replicas.contains(&candidate) {
            replicas.push(candidate);
        }
    }
    replicas
}

async fn send_mailbox(
    client: &reqwest::Client,
    mailbox: &str,
    action: &MailboxRequest,
    recipient: &RecipientKeyPair,
) -> Result<MailboxResponse> {
    let key = client
        .get(format!("{}/key", mailbox.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<u8>>()
        .await?;
    let mailbox_id = mailbox_id(mailbox)?;
    let bytes = serde_json::to_vec(action)?;
    let sealed = seal_to_recipient(
        &key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::mailbox_transport_context(&mailbox_id, "request")?,
    )?;
    let response = client
        .post(mailbox)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    let response = ensure_success(response, "mailbox request")
        .await?
        .json::<SealedMailboxBody>()
        .await?;
    let plaintext = recipient.open(
        &response.sealed,
        &gp_wire::mailbox_transport_context(&mailbox_id, "response")?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

async fn ensure_success(response: reqwest::Response, operation: &str) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("{operation} failed with {status}: {body}")
}

fn mailbox_url(relay: &str) -> String {
    format!(
        "{}/v1/mailboxes/{}",
        relay.trim_end_matches('/'),
        hex::encode(random_id())
    )
}

fn mailbox_id(mailbox_url: &str) -> Result<String> {
    mailbox_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| value.len() >= 32)
        .map(str::to_owned)
        .context("invalid mailbox URL")
}

fn short_mailbox(mailbox: &str) -> String {
    mailbox_id(mailbox)
        .map(|value| format!("{}…", &value[..10]))
        .unwrap_or_else(|_| "invalid".into())
}

fn write_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        options.mode(0o600);
        let mut file = options.open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{mailbox_replicas, required_cancel_acks};

    #[test]
    fn hard_cancel_requires_enough_tombstones_to_break_recovery_quorum() {
        assert_eq!(required_cancel_acks(8, 5).unwrap(), 4);
        assert_eq!(required_cancel_acks(3, 2).unwrap(), 2);
        assert_eq!(required_cancel_acks(8, 1).unwrap(), 8);
        assert!(required_cancel_acks(8, 0).is_err());
        assert!(required_cancel_acks(3, 4).is_err());
    }

    #[test]
    fn relay_failover_preserves_the_opaque_mailbox_id_without_duplicates() {
        let mailbox = "http://relay-1/v1/mailboxes/0123456789abcdef0123456789abcdef";
        assert_eq!(
            mailbox_replicas(
                mailbox,
                &[
                    "http://relay-1".into(),
                    "http://relay-2/".into(),
                    "http://relay-2".into(),
                ],
            ),
            vec![
                mailbox.to_string(),
                "http://relay-2/v1/mailboxes/0123456789abcdef0123456789abcdef".into(),
            ]
        );
    }
}
