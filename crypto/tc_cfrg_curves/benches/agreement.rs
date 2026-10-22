use core::hint::black_box;
use core::time::Duration;

use criterion::Criterion;
use tc_agreement::{Agreement, AgreementInit};
use tc_cfrg_curves::{X25519Agreement, X25519PrivateKey};

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    let c = &mut criterion;

    let private_key = X25519PrivateKey::new([0xA5; 32]);
    let peer = X25519PrivateKey::new([0x5A; 32]).generate_public_key();
    let mut agreement = X25519Agreement::new();
    agreement.init(&private_key).unwrap();
    let mut secret = [0; 32];
    c.bench_function("x25519/generate_public_key", |b| {
        b.iter(|| black_box(&private_key).generate_public_key())
    });
    c.bench_function("x25519/calculate_agreement", |b| {
        b.iter(|| agreement.calculate_agreement(black_box(&peer), &mut secret))
    });

    #[cfg(feature = "x448")]
    {
        use tc_cfrg_curves::{X448Agreement, X448PrivateKey};
        let private_key = X448PrivateKey::new([0xA5; 56]);
        let peer = X448PrivateKey::new([0x5A; 56]).generate_public_key();
        let mut agreement = X448Agreement::new();
        agreement.init(&private_key).unwrap();
        let mut secret = [0; 56];
        c.bench_function("x448/generate_public_key", |b| {
            b.iter(|| black_box(&private_key).generate_public_key())
        });
        c.bench_function("x448/calculate_agreement", |b| {
            b.iter(|| agreement.calculate_agreement(black_box(&peer), &mut secret))
        });
    }

    criterion.final_summary();
}
