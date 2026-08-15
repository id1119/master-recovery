mod client;
mod guardian_runtime;
mod protocol;
mod recovery_runtime;
mod rotation_coordinator;
mod rotation_protocol;
mod rotation_runtime;
mod server;
mod types;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{
    client::{CancelOptions, RecoverOptions, RecoverV3Options, SetupOptions, SetupV3Options},
    server::{NodeRole, ServeConfig},
};

#[derive(Parser)]
#[command(
    name = "gp-network",
    version,
    about = "Guardian Protocol multi-process network runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one long-lived relay, config-store, signer, or guardian node.
    Serve {
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: SocketAddr,
        #[arg(long, default_value = "/data")]
        data_dir: PathBuf,
        #[arg(long, env = "GP_RELAY_ADMIN_TOKEN", default_value = "")]
        relay_token: String,
        #[arg(long, env = "GP_NETWORK_ADMIN_TOKEN", default_value = "")]
        admin_token: String,
        #[arg(long, env = "GP_ALLOW_INSECURE_DEMO_DELAY", default_value_t = false)]
        allow_insecure_demo_delay: bool,
        #[arg(long, env = "GP_AUTO_APPROVE", default_value_t = false)]
        auto_approve: bool,
        #[arg(long, env = "GP_CORRUPT_CONTRIBUTION", default_value_t = false)]
        corrupt_contribution: bool,
    },
    /// Generate and distribute a new configuration over the running network.
    Setup {
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        #[arg(long, required = true)]
        config_store: Vec<String>,
        #[arg(long, required = true)]
        relay: Vec<String>,
        #[arg(long, env = "GP_RELAY_ADMIN_TOKEN")]
        relay_token: String,
        #[arg(long, env = "GP_NETWORK_ADMIN_TOKEN")]
        admin_token: String,
        #[arg(long, required = true)]
        signer: Vec<String>,
        #[arg(long, required = true)]
        guardian: Vec<String>,
        #[arg(long, default_value_t = 2)]
        signer_threshold: u16,
        #[arg(long, default_value_t = 5)]
        guardian_threshold: u16,
        #[arg(long, default_value_t = gp_types::PRODUCTION_MIN_DELAY_SECS)]
        delay_secs: u64,
        #[arg(long, default_value = "/demo/recovery-card.json")]
        card: String,
        #[arg(long, default_value = "/demo/owner-control.json")]
        owner_control: String,
    },
    /// Create and provision a rotatable protocol-v3 configuration.
    SetupV3 {
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        #[arg(long, required = true)]
        relay: Vec<String>,
        #[arg(long, env = "GP_RELAY_ADMIN_TOKEN")]
        relay_token: String,
        #[arg(long, env = "GP_NETWORK_ADMIN_TOKEN")]
        admin_token: String,
        #[arg(long, required = true)]
        signer: Vec<String>,
        #[arg(long, required = true)]
        guardian: Vec<String>,
        #[arg(long, required = true)]
        witness: Vec<String>,
        #[arg(long, default_value_t = 2)]
        signer_threshold: u16,
        #[arg(long, default_value_t = 5)]
        guardian_threshold: u16,
        #[arg(long, default_value_t = 1)]
        witness_fault_bound: u16,
        #[arg(long, default_value_t = gp_types::PRODUCTION_MIN_DELAY_SECS)]
        delay_secs: u64,
        #[arg(long, default_value = "/demo/recovery-card-v3.json")]
        card: String,
        #[arg(long, default_value = "/demo/owner-control-v3.json")]
        owner_control: String,
    },
    /// Recover through actual relay, signer, guardian, and config-store processes.
    Recover {
        #[arg(long, default_value = "/demo/recovery-card.json")]
        card: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        request_out: Option<String>,
        #[arg(long, default_value_t = false)]
        cancel_before_release: bool,
        #[arg(long, default_value = "/demo/owner-control.json")]
        owner_control: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Permanently cancel one exact recovery request with the setup-time owner key.
    Cancel {
        #[arg(long)]
        request: String,
        #[arg(long, default_value = "/demo/owner-control.json")]
        owner_control: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Resolve the highest authenticated protocol-v3 Guardian Epoch.
    DiscoverV3 {
        #[arg(long)]
        card: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Recover through the witness-selected, rotatable protocol-v3 epoch.
    RecoverV3 {
        #[arg(long)]
        card: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        request_out: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Replace one guardian with live RTS + full-roster refresh and witness QC.
    RotateV3 {
        #[arg(long)]
        card: String,
        #[arg(long)]
        owner_control: String,
        #[arg(long)]
        remove_guardian: u16,
        #[arg(long)]
        replacement_guardian: String,
        #[arg(long, env = "GP_RELAY_ADMIN_TOKEN")]
        relay_token: String,
        #[arg(long, env = "GP_NETWORK_ADMIN_TOKEN")]
        admin_token: String,
        /// Private plan/control artifact used for owner cancellation during Delay.
        #[arg(long, default_value = "/demo/rotation-control-v3.json")]
        rotation_control: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Permanently owner-cancel an exact in-flight protocol-v3 rotation.
    CancelRotationV3 {
        #[arg(long)]
        rotation_control: String,
        #[arg(long)]
        owner_control: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Relay,
    ConfigStore,
    Signer,
    Guardian,
    Witness,
}

impl From<RoleArg> for NodeRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Relay => Self::Relay,
            RoleArg::ConfigStore => Self::ConfigStore,
            RoleArg::Signer => Self::Signer,
            RoleArg::Guardian => Self::Guardian,
            RoleArg::Witness => Self::Witness,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve {
            role,
            listen,
            data_dir,
            relay_token,
            admin_token,
            allow_insecure_demo_delay,
            auto_approve,
            corrupt_contribution,
        } => {
            server::serve(ServeConfig {
                role: role.into(),
                listen,
                data_dir,
                relay_token,
                admin_token,
                allow_insecure_demo_delay,
                auto_approve,
                corrupt_contribution,
            })
            .await?;
        }
        Command::Setup {
            secret,
            secret_file,
            config_store,
            relay,
            relay_token,
            admin_token,
            signer,
            guardian,
            signer_threshold,
            guardian_threshold,
            delay_secs,
            card,
            owner_control,
        } => {
            let secret = match (secret, secret_file) {
                (Some(value), None) => value.into_bytes(),
                (None, Some(path)) => std::fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                (None, None) => bail!("provide --secret or --secret-file"),
                (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
            };
            let card = client::setup(SetupOptions {
                secret,
                config_stores: config_store,
                relays: relay,
                relay_token,
                admin_token,
                signers: signer,
                guardians: guardian,
                signer_threshold,
                guardian_threshold,
                delay_secs,
                card_path: card,
                owner_control_path: owner_control,
            })
            .await?;
            println!("Recovery Card config id: {}", hex::encode(card.config_id));
        }
        Command::SetupV3 {
            secret,
            secret_file,
            relay,
            relay_token,
            admin_token,
            signer,
            guardian,
            witness,
            signer_threshold,
            guardian_threshold,
            witness_fault_bound,
            delay_secs,
            card,
            owner_control,
        } => {
            let secret = match (secret, secret_file) {
                (Some(value), None) => value.into_bytes(),
                (None, Some(path)) => std::fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                (None, None) => bail!("provide --secret or --secret-file"),
                (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
            };
            let card = client::setup_v3(SetupV3Options {
                secret,
                relays: relay,
                relay_token,
                admin_token,
                signers: signer,
                guardians: guardian,
                witnesses: witness,
                signer_threshold,
                guardian_threshold,
                witness_fault_bound,
                delay_secs,
                card_path: card,
                owner_control_path: owner_control,
            })
            .await?;
            println!(
                "Recovery Card v3 config id: {}",
                hex::encode(card.config_id)
            );
        }
        Command::Recover {
            card,
            output,
            request_out,
            cancel_before_release,
            owner_control,
            json,
        } => {
            let result = client::recover(RecoverOptions {
                card_path: card,
                output_path: output,
                request_out_path: request_out,
                cancel_before_release,
                owner_control_path: owner_control,
            })
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.cancelled {
                println!("NETWORK RESULT: request permanently cancelled; no plaintext released");
            } else {
                println!(
                    "NETWORK RESULT: recovered {:?}; rejected guardians {:?}",
                    result.recovered_secret, result.rejected_guardians
                );
            }
        }
        Command::Cancel {
            request,
            owner_control,
            json,
        } => {
            let result = client::cancel(CancelOptions {
                request_path: request,
                owner_control_path: owner_control,
            })
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "OWNER HARD CANCEL: request {} permanently cancelled on {} guardians",
                    result.request_id, result.guardian_acknowledgements
                );
            }
        }
        Command::DiscoverV3 { card, json } => {
            let card: gp_types::RecoveryCardV3 =
                serde_json::from_slice(&std::fs::read(&card).with_context(|| {
                    format!(
                        "failed to read protocol-v3 Recovery Card {}",
                        card.display()
                    )
                })?)?;
            let capsule = client::discover_latest_epoch_v3(&reqwest::Client::new(), &card).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&capsule)?);
            } else {
                println!(
                    "ACTIVE GUARDIAN EPOCH: {} capsule={}",
                    capsule.config_ref.guardian_epoch,
                    hex::encode(capsule.capsule_hash)
                );
            }
        }
        Command::RecoverV3 {
            card,
            output,
            request_out,
            json,
        } => {
            let result = client::recover_v3(RecoverV3Options {
                card_path: card,
                output_path: output,
                request_out_path: request_out,
            })
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "NETWORK v3 RESULT: recovered {:?}; rejected guardians {:?}",
                    result.recovered_secret, result.rejected_guardians
                );
            }
        }
        Command::RotateV3 {
            card,
            owner_control,
            remove_guardian,
            replacement_guardian,
            relay_token,
            admin_token,
            rotation_control,
            json,
        } => {
            let result = rotation_coordinator::rotate_v3(rotation_coordinator::RotateV3Options {
                card_path: card,
                owner_control_path: owner_control,
                remove_guardian,
                replacement_target: replacement_guardian,
                relay_token,
                admin_token,
                rotation_control_path: rotation_control,
            })
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "ROTATION v3: epoch {} -> {}, G{} -> G{}, prepared {}, witness acks {}, plaintext decryptions {}",
                    result.predecessor_epoch,
                    result.successor_epoch,
                    result.removed_guardian,
                    result.added_guardian,
                    result.prepared_guardians,
                    result.witness_acknowledgements,
                    result.plaintext_decryptions,
                );
            }
        }
        Command::CancelRotationV3 {
            rotation_control,
            owner_control,
            json,
        } => {
            let result = rotation_coordinator::cancel_rotation_v3(
                rotation_coordinator::CancelRotationV3Options {
                    rotation_control_path: rotation_control,
                    owner_control_path: owner_control,
                },
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "OWNER ROTATION CANCEL v3: request {} permanently cancelled on {}/{} witnesses and {}/{} required old guardians; signer cancellation finalized on {} signers",
                    result.rotation_id,
                    result.witness_acknowledgements,
                    result.required_witness_acknowledgements,
                    result.old_guardian_acknowledgements,
                    result.required_old_guardian_acknowledgements,
                    result.signer_cancel_finalizations,
                );
            }
        }
    }
    Ok(())
}
