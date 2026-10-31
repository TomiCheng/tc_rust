//! `EcnrSigner`：Bouncy Castle `ECNRTest` 的 239 位元質數曲線向量（固定 k）、隨機 k 的
//! 往返、接上 `DsaDigestSigner`，以及錯誤。

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaDigestSigner, DsaInit, DsaKCalculator, RandomDsaKCalculator};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_ecnr::{EcnrError, EcnrSigner};
use tc_fp_curve::named_curves::SECP256R1;
use tc_fp_curve::{FpCtCurve, FpField};
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};

type Curve<'a> = &'a FpCtCurve<'a>;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    let hex = format!("{}{hex}", "0".repeat(hex.len() % 2));
    let Ok(value) = PaddedBigUint::from_be(&bytes(&hex));
    value
}

/// 每次給同一個 k，對應 BC 測試的 `FixedSecureRandom`。
struct FixedK(PaddedBigUint);

impl DsaKCalculator<PaddedBigUint> for FixedK {
    fn init(&mut self, _: &PaddedBigUint, _: &PaddedBigUint, _: &[u8]) {}

    fn next_k(&mut self) -> PaddedBigUint {
        self.0.clone()
    }
}

#[test]
fn the_239_bit_prime_vector_matches_bouncy_castle() {
    let field = FpField::new(integer(
        "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
    ))
    .unwrap();
    let curve = FpCtCurve::new(
        &field,
        &integer("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"),
        &integer("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a"),
        Some(integer(
            "7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    let g = curve
        .decode_point(&bytes(
            "020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
        ))
        .unwrap();
    let q = curve
        .decode_point(&bytes(
            "025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70",
        ))
        .unwrap();
    // BC 的 `BigInteger.ToByteArray` 帶一個正負號位元組。
    let message = bytes("00a9993e364706816aba3e25717850c26c9cd0d89d");

    let mut signer = EcnrSigner::new(FixedK(integer(
        "656c7196bf87dcc5d1f1020906df2782360d36b2de7a17ece37d503784af",
    )));
    signer
        .init(
            &EcPrivateKey::<Curve<'_>>::new(
                g.clone(),
                integer("7ef7c6fabefffdea864206e80b0b08a9331ed93e698561b64ca0f7777f3d"),
            )
            .unwrap(),
        )
        .unwrap();
    let (r, s) = signer.generate_signature(&message).unwrap();
    assert_eq!(
        r,
        integer("2cb7f36803ebb9c427c6371ba42766cb89b2015155ea7478605511ccc54d")
    );
    assert_eq!(
        s,
        integer("7b815630e042ff6b797c432240fb6d20bda91066944803a91eb9b549fa97")
    );

    signer
        .init(&EcPublicKey::<Curve<'_>>::new(g, &q).unwrap())
        .unwrap();
    assert!(signer.verify_signature(&message, &r, &s).unwrap());
    assert!(!signer.verify_signature(&message[1..2], &r, &s).unwrap());
}

fn key_pair<'a>(
    g: <Curve<'a> as tc_ec_core::Curve>::Point,
) -> (EcPublicKey<Curve<'a>>, EcPrivateKey<Curve<'a>>) {
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<Curve<'_>>::new();
    generator
        .init(EcKeyGenerationParams::new(g, &mut rng))
        .unwrap();
    generator.generate_key_pair().unwrap()
}

#[test]
fn random_k_signatures_verify_through_the_digest_signer() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let (public_key, private_key) = key_pair(SECP256R1.ct_generator(&curve));
    let ecnr = || EcnrSigner::new(RandomDsaKCalculator::new(rand::rng()));

    let mut signer = DsaDigestSigner::new(ecnr(), Sha256Digest::new());
    signer.init(&private_key).unwrap();
    signer.update(b"attack at dawn").unwrap();
    let mut first = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut first).unwrap();
    first.truncate(length);
    signer.update(b"attack at dawn").unwrap();
    let mut second = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut second).unwrap();
    second.truncate(length);
    assert_ne!(first, second);

    let mut verifier = DsaDigestSigner::new(ecnr(), Sha256Digest::new());
    verifier.init(&public_key).unwrap();
    for signature in [&first, &second] {
        verifier.update(b"attack at dawn").unwrap();
        assert!(verifier.verify_signature(signature).unwrap());
    }
    verifier.update(b"attack at dusk").unwrap();
    assert!(!verifier.verify_signature(&first).unwrap());
}

#[test]
fn errors_are_reported() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let (public_key, private_key) = key_pair(SECP256R1.ct_generator(&curve));
    let mut signer = EcnrSigner::<Curve<'_>, _>::new(RandomDsaKCalculator::new(rand::rng()));
    assert_eq!(
        signer.generate_signature(&[1]),
        Err(EcnrError::NotInitialized)
    );

    signer.init(&private_key).unwrap();
    // 33 位元組、最高位元為 1 的訊息比 256 位元的 n 多出位元。
    assert_eq!(
        signer.generate_signature(&[0xff; 33]),
        Err(EcnrError::InputTooLarge)
    );
    let zero = PaddedBigUint::from(0u8);
    assert_eq!(
        signer.verify_signature(&[1], &zero, &zero),
        Err(EcnrError::NotForVerifying)
    );

    signer.init(&public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&[1]),
        Err(EcnrError::NotForSigning)
    );
    // r 為零或不小於 n 時不符。
    let n = signer.order().clone();
    assert!(!signer.verify_signature(&[1], &zero, &zero).unwrap());
    assert!(!signer.verify_signature(&[1], &n, &zero).unwrap());
    assert_eq!(
        signer.verify_signature(&[0xff; 33], &PaddedBigUint::from(1u8), &zero),
        Err(EcnrError::InputTooLarge)
    );
}
