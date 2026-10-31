//! `AgreementWithKdf`：以 Bouncy Castle 的 `ECDHWithKdfBasicAgreement`、
//! `ECDHCWithKdfBasicAgreement` 與 `ECMqvWithKdfBasicAgreement` 算出的向量對照（AES-128
//! key wrap、128 位元、KDF 為 SHA-256 的 `ECDHKekGenerator`）；以及錯誤。

use tc_agreement::{Agreement, AgreementInit};
use tc_agreement_kdf::{AgreementWithKdf, AgreementWithKdfError, UkmParams};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdh_kek::EcdhKek;
use tc_ecdh_v2::{EcdhBasicAgreement, EcdhError, EcdhcBasicAgreement};
use tc_ecmqv::{EcMqvBasicAgreement, MqvPrivateParams, MqvPublicParams};
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_curve::named_curves::SECT163K1;
use tc_fp_curve::FpCtCurve;
use tc_fp_curve::named_curves::{SECP256K1, SECP256R1};
use tc_sha::Sha256Digest;

const UKM: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn aes128_wrap() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse().unwrap())
}

fn with_kdf<A>(agreement: A) -> AgreementWithKdf<A, EcdhKek<Sha256Digest>> {
    let kdf = EcdhKek::new(Sha256Digest::default());
    AgreementWithKdf::new(agreement, kdf, aes128_wrap(), 128)
}

/// 私鑰為 `d`（十六進位）的金鑰對。
fn key_pair<C: Curve<Scalar = PaddedBigUint>>(
    g: &C::Point,
    d: &str,
) -> (EcPublicKey<C>, EcPrivateKey<C>) {
    let d = PaddedBigUint::from_be(&bytes(d)).unwrap();
    let q = C::multiply(g, &d);
    (
        EcPublicKey::new(g.clone(), &q).unwrap(),
        EcPrivateKey::new(g.clone(), d).unwrap(),
    )
}

fn derive<A, P>(agreement: A, params: UkmParams<P>, public_key: &A::PublicKey) -> Vec<u8>
where
    A: Agreement + AgreementInit<P>,
    <A as Agreement>::Error: core::fmt::Debug,
    <A as AgreementInit<P>>::Error: core::fmt::Debug,
{
    let mut agreement = with_kdf(agreement);
    agreement.init(&params).unwrap();
    let mut key = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, &mut key).unwrap();
    key
}

#[test]
fn ecdh_with_kdf_matches_bouncy_castle() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    let (alice_public, alice_private) = key_pair::<&FpCtCurve<'_>>(&g, &"11".repeat(32));
    let (bob_public, bob_private) = key_pair::<&FpCtCurve<'_>>(&g, &"22".repeat(32));

    let ukm = |key: &EcPrivateKey<_>| UkmParams::new(key.clone()).with_ukm(UKM.to_vec());
    let key = derive(EcdhBasicAgreement::new(), ukm(&alice_private), &bob_public);
    assert_eq!(key, bytes("85b41b8af1eae80fc72a46097a2dd2ce"));
    assert_eq!(
        key,
        derive(EcdhBasicAgreement::new(), ukm(&bob_private), &alice_public)
    );

    let without_ukm = derive(
        EcdhBasicAgreement::new(),
        UkmParams::new(alice_private),
        &bob_public,
    );
    assert_eq!(without_ukm, bytes("27622a511b87712afeada50f40e8cf27"));
}

#[test]
fn ecdhc_with_kdf_on_sect163k1_matches_bouncy_castle() {
    let curve = SECT163K1.ct_curve();
    let g = SECT163K1.ct_generator(&curve);
    let (alice_public, alice_private) =
        key_pair::<&F2mCtCurve>(&g, "0333333333333333333333333333333333333333");
    let (bob_public, bob_private) =
        key_pair::<&F2mCtCurve>(&g, "0444444444444444444444444444444444444444");

    let ukm = |key: &EcPrivateKey<_>| UkmParams::new(key.clone()).with_ukm(UKM.to_vec());
    let key = derive(EcdhcBasicAgreement::new(), ukm(&alice_private), &bob_public);
    assert_eq!(key, bytes("9174d4a60d2ab7a2ca6649fa8bce39d7"));
    assert_eq!(
        key,
        derive(EcdhcBasicAgreement::new(), ukm(&bob_private), &alice_public)
    );
}

#[test]
fn ecmqv_with_kdf_matches_bouncy_castle() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    let pair = |byte: &str| key_pair::<&FpCtCurve<'_>>(&g, &byte.repeat(32));
    let (alice_static_public, alice_static) = pair("11");
    let (bob_static_public, bob_static) = pair("22");
    let (alice_ephemeral_public, alice_ephemeral) = pair("55");
    let (bob_ephemeral_public, bob_ephemeral) = pair("66");

    let key = derive(
        EcMqvBasicAgreement::new(),
        UkmParams::new(MqvPrivateParams::new(alice_static, alice_ephemeral)).with_ukm(UKM.to_vec()),
        &MqvPublicParams::new(bob_static_public, bob_ephemeral_public),
    );
    assert_eq!(key, bytes("9d884ff7897419c29677c3a1be8b52df"));
    assert_eq!(
        key,
        derive(
            EcMqvBasicAgreement::new(),
            UkmParams::new(MqvPrivateParams::new(bob_static, bob_ephemeral)).with_ukm(UKM.to_vec()),
            &MqvPublicParams::new(alice_static_public, alice_ephemeral_public),
        )
    );
}

#[test]
fn errors_are_reported() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    let other_field = SECP256K1.field();
    let other_curve = SECP256K1.ct_curve(&other_field);
    let other_g = SECP256K1.ct_generator(&other_curve);
    let (public_key, private_key) = key_pair::<&FpCtCurve<'_>>(&g, &"11".repeat(32));
    let (other_public, _) = key_pair::<&FpCtCurve<'_>>(&other_g, &"22".repeat(32));

    let mut agreement = with_kdf(EcdhBasicAgreement::new());
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 16]),
        Err(AgreementWithKdfError::NotInitialized)
    );
    agreement.init(&UkmParams::new(private_key)).unwrap();
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 15]),
        Err(AgreementWithKdfError::BufferTooSmall)
    );
    assert_eq!(
        agreement.calculate_agreement(&other_public, &mut [0; 16]),
        Err(AgreementWithKdfError::Agreement(EcdhError::WrongDomain))
    );
}
