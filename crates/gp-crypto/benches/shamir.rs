use std::{collections::BTreeMap, hint::black_box, time::Duration};

use blahaj::{Share, Sharks};
use criterion::{Criterion, criterion_group, criterion_main};
use gp_crypto::{
    CryptoError, SecretVec, frost_dealer_split, frost_recover_dek, frost_refresh_part1,
    frost_refresh_part2, frost_refresh_part3, recover_secret, split_secret,
};
use rand_chacha08::{ChaCha20Rng, rand_core::SeedableRng};
use zeroize::Zeroizing;

// These two helpers preserve the pre-hardening wrapper for a same-process overhead
// comparison. They are benchmark references only; production calls the validated API.
fn pre_hardening_split(
    secret: &[u8],
    threshold: u16,
    total: u16,
    seed: [u8; 32],
) -> Result<Vec<SecretVec>, CryptoError> {
    if threshold == 0 || threshold > total || total > 255 {
        return Err(CryptoError::InvalidThreshold);
    }
    let scheme = Sharks(threshold as u8);
    let mut rng = ChaCha20Rng::from_seed(seed);
    Ok(scheme
        .dealer_rng(secret, &mut rng)
        .take(total as usize)
        .map(|share| Zeroizing::new(Vec::from(&share)))
        .collect())
}

fn pre_hardening_recover<T: AsRef<[u8]>>(
    shares: &[T],
    threshold: u16,
) -> Result<SecretVec, CryptoError> {
    if shares.len() < threshold as usize {
        return Err(CryptoError::InsufficientShares);
    }
    let decoded: Vec<Share> = shares
        .iter()
        .map(|share| Share::try_from(share.as_ref()).map_err(|_| CryptoError::InvalidShare))
        .collect::<Result<_, _>>()?;
    Sharks(threshold as u8)
        .recover(&decoded)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::InsufficientShares)
}

fn bench_configuration(c: &mut Criterion, label: &str, threshold: u16, total: u16, seed: u8) {
    let secret = [0x5a; 32];

    let mut split = c.benchmark_group(format!("shamir/split/{label}"));
    split.bench_function("pre-hardening-reference", |b| {
        b.iter(|| {
            pre_hardening_split(black_box(&secret), threshold, total, black_box([seed; 32]))
                .unwrap()
        })
    });
    split.bench_function("hardened", |b| {
        b.iter(|| {
            split_secret(black_box(&secret), threshold, total, black_box([seed; 32])).unwrap()
        })
    });
    split.finish();

    let shares = split_secret(&secret, threshold, total, [seed.wrapping_add(1); 32]).unwrap();
    let selected = &shares[..usize::from(threshold)];
    let mut recover = c.benchmark_group(format!("shamir/recover/{label}"));
    recover.bench_function("pre-hardening-reference", |b| {
        b.iter(|| pre_hardening_recover(black_box(selected), threshold).unwrap())
    });
    recover.bench_function("hardened", |b| {
        b.iter(|| recover_secret(black_box(selected), threshold).unwrap())
    });
    recover.finish();
}

fn bench_shamir(c: &mut Criterion) {
    bench_configuration(c, "2-of-3/32-byte", 2, 3, 0x11);
    bench_configuration(c, "5-of-8/32-byte", 5, 8, 0x22);

    let dealer = frost_dealer_split(5, 8, [0x31; 32]).unwrap();
    c.bench_function("frost/dealer-split/5-of-8", |b| {
        b.iter(|| frost_dealer_split(5, 8, black_box([0x32; 32])).unwrap())
    });
    c.bench_function("frost/recover/5-of-8", |b| {
        b.iter(|| frost_recover_dek(black_box(&dealer.shares[..5]), 5).unwrap())
    });
    c.bench_function("frost/full-roster-refresh/5-of-8", |b| {
        b.iter(|| run_full_roster_refresh(black_box(&dealer)).unwrap())
    });
}

fn run_full_roster_refresh(
    dealer: &gp_crypto::FrostDealerOutput,
) -> Result<Vec<SecretVec>, CryptoError> {
    let participants = (1..=8_u16).collect::<Vec<_>>();
    let round1 = participants
        .iter()
        .map(|participant| {
            Ok((
                *participant,
                frost_refresh_part1(*participant, 5, 8, [*participant as u8; 32])?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CryptoError>>()?;
    let round2 = participants
        .iter()
        .map(|participant| {
            let incoming = round1
                .iter()
                .filter(|(sender, _)| sender != &participant)
                .map(|(sender, package)| (*sender, package.broadcast.clone()))
                .collect::<Vec<_>>();
            Ok((
                *participant,
                frost_refresh_part2(&round1[participant].secret_state, &incoming)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CryptoError>>()?;
    participants
        .iter()
        .map(|participant| {
            let incoming1 = round1
                .iter()
                .filter(|(sender, _)| *sender != participant)
                .map(|(sender, package)| (*sender, package.broadcast.clone()))
                .collect::<Vec<_>>();
            let incoming2 = round2
                .iter()
                .filter(|(sender, _)| *sender != participant)
                .map(|(sender, package)| {
                    let message = package
                        .direct_messages
                        .iter()
                        .find(|(recipient, _)| recipient == participant)
                        .expect("complete refresh package")
                        .1
                        .clone();
                    (*sender, message)
                })
                .collect::<Vec<_>>();
            frost_refresh_part3(
                &round2[participant].secret_state,
                &incoming1,
                &incoming2,
                &dealer.public_package,
                &dealer.shares[usize::from(*participant - 1)],
            )
            .map(|output| output.share)
        })
        .collect()
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_shamir
}
criterion_main!(benches);
