use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use gp_sim::{DemoOptions, DemoResult, run_demo};
use gp_types::MetadataMode;

#[derive(Parser)]
#[command(name = "gp", version, about = "Guardian Protocol hackathon prototype")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the complete setup, delayed recovery, and replacement demo.
    Demo(DemoArgs),
    /// Run the setup-time owner-key hard-cancellation race.
    Cancel(DemoArgs),
    /// Replay one seed in OFF, BASIC, and STRONG metadata modes.
    Compare(DemoArgs),
    /// Start the browser-based visual simulator.
    Serve {
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
}

#[derive(Clone, Args)]
struct DemoArgs {
    #[arg(long, default_value_t = 424_242)]
    seed: u64,
    #[arg(long, value_enum, default_value_t = ModeArg::Strong)]
    mode: ModeArg,
    #[arg(long, default_value = "correct horse battery staple")]
    secret: String,
    #[arg(long, default_value_t = 3)]
    offline_signer: u16,
    #[arg(long, default_value_t = 0)]
    offline_guardian: u16,
    #[arg(long, default_value_t = 1)]
    corrupt_guardian: u16,
    #[arg(long, default_value_t = 3)]
    signer_count: u16,
    #[arg(long, default_value_t = 2)]
    signer_threshold: u16,
    #[arg(long, default_value_t = 8)]
    guardian_count: u16,
    #[arg(long, default_value_t = 5)]
    guardian_threshold: u16,
    #[arg(long, default_value_t = 5)]
    delay_seconds: u64,
    #[arg(long, default_value_t = 120)]
    latency_ms: u64,
    #[arg(long, default_value_t = 0)]
    loss_percent: u8,
    #[arg(long, default_value_t = 0)]
    duplication_percent: u8,
    #[arg(long, default_value_t = 0)]
    mix_drop_percent: u8,
    #[arg(long, default_value_t = 3)]
    cover_rate: u16,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Off,
    Basic,
    Strong,
}

impl From<ModeArg> for MetadataMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Off => Self::Off,
            ModeArg::Basic => Self::Basic,
            ModeArg::Strong => Self::Strong,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Demo(args) => display(run(&args, false)?, args.json)?,
        Command::Cancel(args) => display(run(&args, true)?, args.json)?,
        Command::Compare(args) => {
            let mut results = Vec::new();
            for mode in [ModeArg::Off, ModeArg::Basic, ModeArg::Strong] {
                let mut current = args.clone();
                current.mode = mode;
                results.push(run(&current, false)?);
            }
            if args.json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                println!("METADATA REPLAY COMPARISON · seed {}", args.seed);
                for result in results {
                    println!(
                        "{:?}: observed={} cover={} fixed-format={} trivially-isolatable={} · {}",
                        result.mode,
                        result.observer.total_observed_packets,
                        result.observer.cover_packets,
                        result.observer.fixed_outer_format,
                        result.observer.trivially_isolatable,
                        result.observer.remaining_leakage
                    );
                }
            }
        }
        Command::Serve { port } => gp_gui_sim::serve(port).await?,
    }
    Ok(())
}

fn run(args: &DemoArgs, cancel: bool) -> Result<DemoResult> {
    Ok(run_demo(&DemoOptions {
        seed: args.seed,
        mode: args.mode.into(),
        secret: args.secret.clone(),
        offline_signer: nonzero(args.offline_signer),
        offline_guardian: nonzero(args.offline_guardian),
        corrupt_guardian: nonzero(args.corrupt_guardian),
        cancel_before_release: cancel,
        simulated_delay_secs: args.delay_seconds,
        signer_count: args.signer_count,
        signer_threshold: args.signer_threshold,
        guardian_count: args.guardian_count,
        guardian_threshold: args.guardian_threshold,
        network_latency_ms: args.latency_ms,
        packet_loss_percent: args.loss_percent,
        packet_duplication_percent: args.duplication_percent,
        mix_drop_percent: args.mix_drop_percent,
        cover_rate: args.cover_rate,
    })?)
}

fn nonzero(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}

fn display(result: DemoResult, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    println!(
        "Guardian Protocol · seed {} · {:?} · {:?}",
        result.seed, result.mode, result.final_state
    );
    for event in &result.events {
        println!(
            "t+{:02}s {:<9} {:<14} {}",
            event.at, event.phase, event.actor, event.message
        );
    }
    println!(
        "guardians: {} valid, {:?} rejected · observer: {} packets ({} cover)",
        result.valid_guardians,
        result.rejected_guardians,
        result.observer.total_observed_packets,
        result.observer.cover_packets
    );
    if let Some(secret) = &result.recovered_secret {
        println!("recovered locally: {secret}");
    }
    println!("{}", result.security_notice);
    Ok(())
}
