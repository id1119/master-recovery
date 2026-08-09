mod client;
mod protocol;
mod server;
mod types;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{
    client::{RecoverOptions, SetupOptions},
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
        #[arg(long, default_value_t = 2)]
        cancellation_threshold: u16,
        #[arg(long, default_value_t = 5)]
        guardian_threshold: u16,
        #[arg(long, default_value_t = gp_types::PRODUCTION_MIN_DELAY_SECS)]
        delay_secs: u64,
        #[arg(long, default_value = "/demo/recovery-card.json")]
        card: String,
    },
    /// Recover through actual relay, signer, guardian, and config-store processes.
    Recover {
        #[arg(long, default_value = "/demo/recovery-card.json")]
        card: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = false)]
        cancel_before_release: bool,
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
}

impl From<RoleArg> for NodeRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Relay => Self::Relay,
            RoleArg::ConfigStore => Self::ConfigStore,
            RoleArg::Signer => Self::Signer,
            RoleArg::Guardian => Self::Guardian,
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
            cancellation_threshold,
            guardian_threshold,
            delay_secs,
            card,
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
                cancellation_threshold,
                guardian_threshold,
                delay_secs,
                card_path: card,
            })
            .await?;
            println!("Recovery Card config id: {}", hex::encode(card.config_id));
        }
        Command::Recover {
            card,
            output,
            cancel_before_release,
            json,
        } => {
            let result = client::recover(RecoverOptions {
                card_path: card,
                output_path: output,
                cancel_before_release,
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
    }
    Ok(())
}
