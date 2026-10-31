//! `EcVkoAgreement`：RFC 7836 附錄 B 例 7（Bouncy Castle `ECVkoTest`），在
//! id-tc26-gost-3410-12-512-paramSetA 上以 GOST R 34.11-2012 256 位元雜湊；隨機金鑰雙方
//! 一致；以及錯誤。

use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_ecvko::{EcVkoAgreement, EcVkoError, EcVkoParams};
use tc_fp_curve::named_curves::{SECP256K1, SECP256R1};
use tc_fp_curve::{FpCtCurve, FpField};
use tc_gost3411::Gost3411_2012_256Digest;

type Curve<'a> = &'a FpCtCurve<'a>;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn big_endian(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_be(&bytes(hex)).unwrap()
}

/// RFC 7836 以小端序寫出整數。
fn little_endian(hex: &str) -> PaddedBigUint {
    let mut bytes = bytes(hex);
    bytes.reverse();
    PaddedBigUint::from_be(&bytes).unwrap()
}

fn agree<C: tc_ec_core::Curve<Scalar = PaddedBigUint>>(
    private_key: &EcPrivateKey<C>,
    ukm: &[u8],
    public_key: &EcPublicKey<C>,
) -> Result<Vec<u8>, EcVkoError> {
    let mut agreement = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
    agreement.init(&EcVkoParams::new(private_key.clone(), ukm.to_vec()))?;
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

#[test]
fn rfc_7836_example_7_matches_bouncy_castle() {
    let field = FpField::new(big_endian(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
    ))
    .unwrap();
    let curve = FpCtCurve::new(
        &field,
        &big_endian(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
        ),
        &big_endian(
            "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
        ),
        Some(big_endian(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &PaddedBigUint::from(3u8),
            &big_endian(
                "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
            ),
        )
        .unwrap();
    let key_pair = |d: &str, x: &str, y: &str| {
        let q = curve
            .create_point(&little_endian(x), &little_endian(y))
            .unwrap();
        (
            EcPrivateKey::<Curve<'_>>::new(g.clone(), little_endian(d)).unwrap(),
            EcPublicKey::<Curve<'_>>::new(g.clone(), &q).unwrap(),
        )
    };
    let (alice_private, alice_public) = key_pair(
        "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667",
        "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7",
        "914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a",
    );
    let (bob_private, bob_public) = key_pair(
        "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db",
        "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651",
        "04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79",
    );
    let ukm = [0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27];
    let secret = agree(&alice_private, &ukm, &bob_public).unwrap();
    assert_eq!(secret, agree(&bob_private, &ukm, &alice_public).unwrap());
    assert_eq!(
        secret,
        bytes("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")
    );
}

#[test]
fn random_keys_agree_and_the_ukm_changes_the_secret() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<Curve<'_>>::new();
    generator
        .init(EcKeyGenerationParams::new(
            SECP256R1.ct_generator(&curve),
            &mut rng,
        ))
        .unwrap();
    let (alice_public, alice_private) = generator.generate_key_pair().unwrap();
    let (bob_public, bob_private) = generator.generate_key_pair().unwrap();
    let ukm = rand::random::<[u8; 8]>();
    let secret = agree(&alice_private, &ukm, &bob_public).unwrap();
    assert_eq!(secret, agree(&bob_private, &ukm, &alice_public).unwrap());
    assert_eq!(secret.len(), 32);

    let mut other_ukm = ukm;
    other_ukm[0] ^= 1;
    assert_ne!(
        secret,
        agree(&alice_private, &other_ukm, &bob_public).unwrap()
    );
}

#[test]
fn errors_are_reported() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let other_field = SECP256K1.field();
    let other_curve = SECP256K1.ct_curve(&other_field);
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<Curve<'_>>::new();
    generator
        .init(EcKeyGenerationParams::new(
            SECP256R1.ct_generator(&curve),
            &mut rng,
        ))
        .unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();
    let mut other = EcKeyPairGenerator::<Curve<'_>>::new();
    other
        .init(EcKeyGenerationParams::new(
            SECP256K1.ct_generator(&other_curve),
            &mut rng,
        ))
        .unwrap();
    let (other_public, _) = other.generate_key_pair().unwrap();

    let uninitialized = EcVkoAgreement::<Curve<'_>, _>::new(Gost3411_2012_256Digest::default());
    assert_eq!(
        uninitialized.calculate_agreement(&public_key, &mut [0; 32]),
        Err(EcVkoError::NotInitialized)
    );
    assert_eq!(
        agree(&private_key, &[1], &other_public),
        Err(EcVkoError::DomainMismatch)
    );
    // UKM 為零時 h·UKM·d 是零，共享點是無窮遠點。
    assert_eq!(
        agree(&private_key, &[0; 8], &public_key),
        Err(EcVkoError::InvalidAgreement)
    );

    let mut agreement = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
    agreement
        .init(&EcVkoParams::new(private_key, vec![1]))
        .unwrap();
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 31]),
        Err(EcVkoError::BufferTooSmall)
    );
}
