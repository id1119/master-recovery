use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use gp_crypto::{RecipientKeyPair, seal_to_recipient};
use gp_types::{
    BeginRecoveryCertificate, CancelCertificate, ConfigCapsule, RecoveryCard, RecoveryRequest,
    ReleaseCertificate, SetupPolicy,
};

use crate::{
    protocol::{
        create_setup, open_descriptor, random_id, random_nonce, reconstruct_a, reconstruct_payload,
        validate_capsule, validate_guardian_contribution, wall_now,
    },
    types::{
        MailboxRequest, MailboxResponse, NetworkDemoResult, NodeInfo, ProvisionPayload,
        RouteRegistration, SealedMailboxBody,
    },
};

pub struct SetupOptions {
    pub secret: Vec<u8>,
    pub config_store: String,
    pub relay: String,
    pub relay_token: String,
    pub admin_token: String,
    pub signers: Vec<String>,
    pub guardians: Vec<String>,
    pub signer_threshold: u16,
    pub cancellation_threshold: u16,
    pub guardian_threshold: u16,
    pub delay_secs: u64,
    pub card_path: String,
}

pub struct RecoverOptions {
    pub card_path: String,
    pub output_path: Option<String>,
    pub cancel_before_release: bool,
}

pub async fn setup(options: SetupOptions) -> Result<RecoveryCard> {
    let client = reqwest::Client::new();
    if options.signers.is_empty() || options.guardians.is_empty() {
        bail!("at least one signer and guardian node is required");
    }
    let signer_count = u16::try_from(options.signers.len())?;
    let guardian_count = u16::try_from(options.guardians.len())?;
    let signer_mailboxes = (0..options.signers.len())
        .map(|_| mailbox_url(&options.relay))
        .collect::<Vec<_>>();
    let guardian_mailboxes = (0..options.guardians.len())
        .map(|_| mailbox_url(&options.relay))
        .collect::<Vec<_>>();
    let policy = SetupPolicy {
        signer_count,
        signer_threshold: options.signer_threshold,
        cancellation_threshold: options.cancellation_threshold,
        guardian_count,
        guardian_threshold: options.guardian_threshold,
        minimum_recovery_delay: options.delay_secs,
    };
    let bundle = create_setup(
        &options.secret,
        &policy,
        signer_mailboxes,
        guardian_mailboxes,
        &options.config_store,
    )?;

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
        register_route(
            &client,
            &options.relay,
            &options.relay_token,
            mailbox,
            target,
        )
        .await?;
        println!("  provisioned signer mailbox {}", short_mailbox(mailbox));
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
        register_route(
            &client,
            &options.relay,
            &options.relay_token,
            &mailbox,
            target,
        )
        .await?;
        println!("  provisioned guardian mailbox {}", short_mailbox(&mailbox));
    }

    let config_id = hex::encode(bundle.capsule.config_id);
    let response = client
        .put(format!(
            "{}/v1/configs/{config_id}",
            options.config_store.trim_end_matches('/')
        ))
        .bearer_auth(&options.admin_token)
        .json(&bundle.capsule)
        .send()
        .await?;
    ensure_success(response, "publish Config Capsule").await?;
    write_private_json(Path::new(&options.card_path), &bundle.card)?;
    println!("  published Config Capsule and wrote {}", options.card_path);
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
    let capsule = client
        .get(&card.capsule_locator)
        .send()
        .await?
        .error_for_status()?
        .json::<ConfigCapsule>()
        .await?;
    validate_capsule(&card, &capsule)?;
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
    println!("RECOVERY request={}", hex::encode(request.request_id));

    let mut signer_contributions = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_mailbox(
            &client,
            mailbox,
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
        match send_mailbox(
            &client,
            &route.mailbox,
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
        // Capture a threshold-valid release certificate before cancellation to model a hostile
        // client racing a previously obtained certificate against the cancellation tombstone.
        let mut pre_cancel_release_votes = Vec::new();
        for mailbox in &card.signer_mailboxes {
            if let Ok(MailboxResponse::ReleaseVote(vote)) = send_mailbox(
                &client,
                mailbox,
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
        let mut votes = Vec::new();
        for mailbox in &card.signer_mailboxes {
            match send_mailbox(
                &client,
                mailbox,
                &MailboxRequest::SignerCancel {
                    request: request.clone(),
                    reason_code: 1,
                },
                &recipient,
            )
            .await
            {
                Ok(MailboxResponse::CancelVote(vote)) => votes.push(vote),
                Ok(_) => {}
                Err(error) => println!("  cancel signer unavailable: {error}"),
            }
            if votes.len() >= usize::from(capsule.cancellation_threshold) {
                break;
            }
        }
        if votes.len() < usize::from(capsule.cancellation_threshold) {
            bail!("cancellation threshold was not reached");
        }
        let certificate = CancelCertificate { votes };
        let mut cancelled_guardians = 0;
        for route in &descriptor.guardians {
            if matches!(
                send_mailbox(
                    &client,
                    &route.mailbox,
                    &MailboxRequest::GuardianCancel {
                        request: request.clone(),
                        certificate: certificate.clone(),
                    },
                    &recipient,
                )
                .await,
                Ok(MailboxResponse::CancellationAccepted)
            ) {
                cancelled_guardians += 1;
            }
        }
        if cancelled_guardians < usize::from(capsule.guardian_threshold) {
            bail!("cancellation did not reach enough guardians");
        }
        println!("  cancellation tombstone stored by {cancelled_guardians} guardians");
        tokio::time::sleep(Duration::from_secs(
            capsule.minimum_recovery_delay.saturating_add(1),
        ))
        .await;
        let mut observed_refusal = false;
        for route in &descriptor.guardians {
            match send_mailbox(
                &client,
                &route.mailbox,
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
        match send_mailbox(
            &client,
            mailbox,
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
        match send_mailbox(
            &client,
            &route.mailbox,
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
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
