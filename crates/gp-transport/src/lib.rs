//! Direct and metadata-resistant simulated transports.

use gp_crypto::{CryptoError, seal_to_recipient};
use gp_types::{Id32, MetadataMode, SealedMessage};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    pub mode: MetadataMode,
    pub base_latency_ms: u64,
    pub epoch_ms: u64,
    pub cover_rate: u16,
    pub hops: u8,
    pub cell_size: usize,
    pub loss_percent: u8,
    pub duplicate_percent: u8,
    pub mix_drop_percent: u8,
}

impl TransportConfig {
    #[must_use]
    pub fn for_mode(mode: MetadataMode) -> Self {
        match mode {
            MetadataMode::Off => Self {
                mode,
                base_latency_ms: 10,
                epoch_ms: 0,
                cover_rate: 0,
                hops: 1,
                cell_size: 0,
                loss_percent: 0,
                duplicate_percent: 0,
                mix_drop_percent: 0,
            },
            MetadataMode::Basic => Self {
                mode,
                base_latency_ms: 80,
                epoch_ms: 0,
                cover_rate: 0,
                hops: 3,
                cell_size: 0,
                loss_percent: 0,
                duplicate_percent: 0,
                mix_drop_percent: 0,
            },
            MetadataMode::Strong => Self {
                mode,
                base_latency_ms: 120,
                epoch_ms: 250,
                cover_rate: 3,
                hops: 3,
                cell_size: 2048,
                loss_percent: 0,
                duplicate_percent: 0,
                mix_drop_percent: 0,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObserverPacket {
    pub timestamp_ms: u64,
    pub size_bucket: usize,
    pub previous_hop: String,
    pub next_hop: String,
    pub outer_format: String,
    pub epoch: u64,
    pub mailbox_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObserverSummary {
    pub mode: MetadataMode,
    pub real_packets_kernel_only: usize,
    pub total_observed_packets: usize,
    pub attempted_packets: usize,
    pub dropped_packets: usize,
    pub duplicated_packets: usize,
    pub cover_packets: usize,
    pub fixed_outer_format: bool,
    pub trivially_isolatable: bool,
    pub remaining_leakage: String,
    pub packets: Vec<ObserverPacket>,
}

#[derive(Clone, Debug)]
struct KernelPacket {
    visible: ObserverPacket,
    is_real: bool,
}

pub fn protect_payload(
    recipient: &[u8],
    kem_seed: Id32,
    nonce: [u8; 24],
    plaintext: &[u8],
    context: &[u8],
) -> Result<SealedMessage, CryptoError> {
    seal_to_recipient(recipient, kem_seed, nonce, plaintext, context)
}

#[must_use]
pub fn simulate_observer(
    config: &TransportConfig,
    seed: u64,
    real_messages: usize,
    payload_size: usize,
) -> ObserverSummary {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut packets = Vec::new();
    let real_cells = if config.mode == MetadataMode::Strong {
        payload_size.div_ceil(config.cell_size).max(1) * real_messages
    } else {
        real_messages
    };
    for message in 0..real_cells {
        append_route(&mut packets, config, &mut rng, message, true, payload_size);
    }

    let cover_messages = if config.mode == MetadataMode::Strong {
        usize::from(config.cover_rate) * 12
    } else {
        0
    };
    for message in 0..cover_messages {
        append_route(
            &mut packets,
            config,
            &mut rng,
            real_cells + message,
            false,
            config.cell_size,
        );
    }
    let attempted_packets = packets.len();
    packets.retain(|packet| {
        let network_drop = rng.random_range(0..100) < config.loss_percent.min(100);
        let touches_mix = packet.visible.previous_hop.starts_with("mix-")
            || packet.visible.next_hop.starts_with("mix-");
        let mix_drop = touches_mix && rng.random_range(0..100) < config.mix_drop_percent.min(100);
        !network_drop && !mix_drop
    });
    let dropped_packets = attempted_packets - packets.len();
    let duplicates: Vec<_> = packets
        .iter()
        .filter(|_| rng.random_range(0..100) < config.duplicate_percent.min(100))
        .cloned()
        .map(|mut packet| {
            packet.visible.timestamp_ms = packet.visible.timestamp_ms.saturating_add(1);
            packet
        })
        .collect();
    let duplicated_packets = duplicates.len();
    packets.extend(duplicates);
    packets.sort_by_key(|packet| packet.visible.timestamp_ms);
    let visible = packets
        .iter()
        .map(|packet| packet.visible.clone())
        .collect();
    let real_count = packets.iter().filter(|packet| packet.is_real).count();
    let cover_count = packets.len() - real_count;
    ObserverSummary {
        mode: config.mode,
        real_packets_kernel_only: real_count,
        total_observed_packets: packets.len(),
        attempted_packets,
        dropped_packets,
        duplicated_packets,
        cover_packets: cover_count,
        fixed_outer_format: config.mode == MetadataMode::Strong,
        trivially_isolatable: config.mode == MetadataMode::Off,
        remaining_leakage: match config.mode {
            MetadataMode::Off => "Endpoints, timing, volume, and approximate payload size are visible.".into(),
            MetadataMode::Basic => "A global observer still sees timing, volume, and variable packet sizes.".into(),
            MetadataMode::Strong => "Timing, total volume, adjacent hops, size bucket, and endpoint participation remain visible.".into(),
        },
        packets: visible,
    }
}

fn append_route(
    output: &mut Vec<KernelPacket>,
    config: &TransportConfig,
    rng: &mut StdRng,
    sequence: usize,
    is_real: bool,
    payload_size: usize,
) {
    let hops = usize::from(config.hops.max(1));
    let base = sequence as u64 * config.base_latency_ms;
    let epoch = if config.epoch_ms == 0 {
        0
    } else {
        base.div_ceil(config.epoch_ms)
    };
    let epoch_start = epoch * config.epoch_ms;
    for hop in 0..hops {
        let mailbox_tag = format!("mbx-{epoch:04x}-{hop:02x}-{:04x}", rng.random::<u16>());
        let jitter = if config.mode == MetadataMode::Off {
            0
        } else {
            rng.random_range(5..=config.base_latency_ms.max(5))
        };
        let timestamp_ms = if config.mode == MetadataMode::Strong {
            epoch_start + jitter + hop as u64 * 7
        } else {
            base + jitter + hop as u64 * config.base_latency_ms
        };
        let size_bucket = if config.mode == MetadataMode::Strong {
            config.cell_size
        } else if payload_size <= 1024 {
            1024
        } else {
            payload_size.next_power_of_two()
        };
        output.push(KernelPacket {
            visible: ObserverPacket {
                timestamp_ms,
                size_bucket,
                previous_hop: if hop == 0 {
                    "opaque-client".into()
                } else {
                    format!("mix-{hop}")
                },
                next_hop: if hop + 1 == hops {
                    "opaque-mailbox".into()
                } else {
                    format!("mix-{}", hop + 1)
                },
                outer_format: if config.mode == MetadataMode::Strong {
                    "gp-cell/v1".into()
                } else {
                    "encrypted-envelope".into()
                },
                epoch,
                mailbox_tag,
            },
            is_real,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_mode_real_and_dummy_formats_match() {
        let summary =
            simulate_observer(&TransportConfig::for_mode(MetadataMode::Strong), 7, 2, 3000);
        assert!(summary.cover_packets > 0);
        assert!(
            summary
                .packets
                .iter()
                .all(|packet| packet.outer_format == "gp-cell/v1")
        );
        assert!(
            summary
                .packets
                .iter()
                .all(|packet| packet.size_bucket == 2048)
        );
    }

    #[test]
    fn same_seed_same_observer_view() {
        let config = TransportConfig::for_mode(MetadataMode::Basic);
        assert_eq!(
            simulate_observer(&config, 11, 5, 200),
            simulate_observer(&config, 11, 5, 200)
        );
    }

    #[test]
    fn network_fault_controls_are_deterministic() {
        let mut duplicated = TransportConfig::for_mode(MetadataMode::Strong);
        duplicated.duplicate_percent = 100;
        let doubled = simulate_observer(&duplicated, 9, 1, 100);

        let baseline =
            simulate_observer(&TransportConfig::for_mode(MetadataMode::Strong), 9, 1, 100);
        assert_eq!(
            doubled.total_observed_packets,
            baseline.total_observed_packets * 2
        );

        let mut dropped = TransportConfig::for_mode(MetadataMode::Strong);
        dropped.loss_percent = 100;
        assert_eq!(
            simulate_observer(&dropped, 9, 1, 100).total_observed_packets,
            0
        );
    }

    fn tag_shape(tag: &str, epoch: u64, hop: u8) -> bool {
        // Exactly the `mbx-{epoch:04x}-{hop:02x}-{rnd:04x}` shape: fixed
        // prefix plus a 4-hex-digit suffix.
        let prefix = format!("mbx-{epoch:04x}-{hop:02x}-");
        tag.len() == prefix.len() + 4
            && tag.starts_with(&prefix)
            && tag.as_bytes()[prefix.len()..]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit())
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        #[test]
        fn strong_mode_outer_fields_are_indistinguishable(
            seed in 0_u64..1_000_000,
            real_messages in 1_usize..=8,
            payload_size in 1_usize..=8192,
        ) {
            let config = TransportConfig::for_mode(MetadataMode::Strong);
            let summary = simulate_observer(&config, seed, real_messages, payload_size);
            let packets = &summary.packets;

            assert!(summary.fixed_outer_format);
            assert!(!summary.trivially_isolatable);
            assert!(!packets.is_empty());
            assert!(summary.cover_packets > 0, "cover traffic must be present");

            // The outer fields an observer can read are structurally identical
            // for every packet: fixed format, fixed size bucket, fixed route
            // shapes, identical mailbox-tag shape.
            for packet in packets {
                assert_eq!(packet.outer_format, "gp-cell/v1");
                assert_eq!(packet.size_bucket, config.cell_size);
                assert_eq!(packet.size_bucket, 2048);
                match packet.previous_hop.as_str() {
                    "opaque-client" => {
                        assert_eq!(packet.next_hop, "mix-1");
                        assert!(tag_shape(&packet.mailbox_tag, packet.epoch, 0));
                    }
                    "mix-1" => {
                        assert_eq!(packet.next_hop, "mix-2");
                        assert!(tag_shape(&packet.mailbox_tag, packet.epoch, 1));
                    }
                    "mix-2" => {
                        assert_eq!(packet.next_hop, "opaque-mailbox");
                        assert!(tag_shape(&packet.mailbox_tag, packet.epoch, 2));
                    }
                    other => panic!("unexpected previous hop {other:?}"),
                }
            }

            // The observable outer-field space is exactly the fixed 3-hop
            // topology with one format and one size bucket: there is no
            // field on which a real packet can be told apart from a dummy.
            let shapes: std::collections::BTreeSet<_> = packets
                .iter()
                .map(|packet| {
                    (
                        packet.outer_format.clone(),
                        packet.size_bucket,
                        packet.previous_hop.clone(),
                        packet.next_hop.clone(),
                    )
                })
                .collect();
            let expected: std::collections::BTreeSet<_> = [
                ("gp-cell/v1".to_string(), 2048, "opaque-client".to_string(), "mix-1".to_string()),
                ("gp-cell/v1".to_string(), 2048, "mix-1".to_string(), "mix-2".to_string()),
                ("gp-cell/v1".to_string(), 2048, "mix-2".to_string(), "opaque-mailbox".to_string()),
            ]
            .into_iter()
            .collect();
            assert_eq!(shapes, expected, "observer must see only the fixed route shapes");
        }

        #[test]
        fn strong_mode_deterministic_replay(
            seed in 0_u64..1_000_000,
            real_messages in 1_usize..=8,
            payload_size in 1_usize..=8192,
        ) {
            let config = TransportConfig::for_mode(MetadataMode::Strong);
            let first = simulate_observer(&config, seed, real_messages, payload_size);
            let second = simulate_observer(&config, seed, real_messages, payload_size);
            assert_eq!(first, second, "same seed must give the identical observer view");
        }
    }
}
