//! `EcMqvBasicAgreement`：Bouncy Castle `ECTest` 的兩組 GEC-2 向量（secp160r1 與餘因子為 2
//! 的 sect163k1）、雙方在幾條曲線上得到同一個秘密，以及錯誤。

use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::Curve;
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_ecmqv::{EcMqvBasicAgreement, EcMqvError, MqvPrivateParams, MqvPublicParams};
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_curve::named_curves::{SECT163K1, SECT283K1};
use tc_fp_curve::FpCtCurve;
use tc_fp_curve::named_curves::{SECP256K1, SECP256R1};
use tc_fp_custom::named_curves::SECP160R1;
use tc_fp_custom::{SecP160R1FieldElement, SecPCtCurve};

type Pair<C> = (EcPublicKey<C>, EcPrivateKey<C>);

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn agree<C: Curve<Scalar = PaddedBigUint>>(
    own: (&Pair<C>, &Pair<C>),
    other: (&Pair<C>, &Pair<C>),
) -> Result<Vec<u8>, EcMqvError> {
    let mut agreement = EcMqvBasicAgreement::new();
    agreement.init(&MqvPrivateParams::new(own.0.1.clone(), own.1.1.clone()))?;
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(
        &MqvPublicParams::new(other.0.0.clone(), other.1.0.clone()),
        &mut secret,
    )?;
    Ok(secret)
}

/// BC 的 `calculateAgreement`：U 與 V 各自算出的值要相同，回傳 U 的。
fn known_answer<C: Curve<Scalar = PaddedBigUint>>(
    g: &C::Point,
    decode: impl Fn(&[u8]) -> C::Point,
    keys: [(&str, &str); 4],
) -> Vec<u8> {
    let [u1, u2, v1, v2] = keys.map(|(q, d)| {
        let private_key =
            EcPrivateKey::<C>::new(g.clone(), PaddedBigUint::from_be(&bytes(d)).unwrap()).unwrap();
        let public_key = EcPublicKey::<C>::new(g.clone(), &decode(&bytes(q))).unwrap();
        (public_key, private_key)
    });
    let secret = agree((&u1, &u2), (&v1, &v2)).unwrap();
    assert_eq!(secret, agree((&v1, &v2), (&u1, &u2)).unwrap());
    secret
}

#[test]
fn the_gec2_vector_on_secp160r1_matches_bouncy_castle() {
    let curve = SECP160R1.ct_curve();
    let g = SECP160R1.ct_generator(&curve);
    let secret = known_answer::<&SecPCtCurve<SecP160R1FieldElement>>(
        &g,
        |encoded| curve.decode_point(encoded).unwrap(),
        [
            (
                "0251B4496FECC406ED0E75A24A3C03206251419DC0",
                "AA374FFC3CE144E6B073307972CB6D57B2A4E982",
            ),
            (
                "03D99CE4D8BF52FA20BD21A962C6556B0F71F4CA1F",
                "149EC7EA3A220A887619B3F9E5B4CA51C7D1779C",
            ),
            (
                "0349B41E0E9C0369C2328739D90F63D56707C6E5BC",
                "45FB58A92A17AD4B15101C66E74F277E2B460866",
            ),
            (
                "02706E5D6E1F640C6E9C804E75DBC14521B1E5F3B5",
                "18C13FCED9EADF884F7C595C8CB565DEFD0CB41E",
            ),
        ],
    );
    assert_eq!(secret, bytes("5A6955CEFDB4E43255FB7FCF718611E4DF8E05AC"));
}

#[test]
fn the_gec2_vector_on_sect163k1_with_cofactor_two_matches_bouncy_castle() {
    let curve = SECT163K1.ct_curve();
    let g = SECT163K1.ct_generator(&curve);
    let secret = known_answer::<&F2mCtCurve>(
        &g,
        |encoded| curve.decode_point(encoded).unwrap(),
        [
            (
                "03037D529FA37E42195F10111127FFB2BB38644806BC",
                "03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D",
            ),
            (
                "02015198E74BC2F1E5C9A62B80248DF0D62B9ADF8429",
                "032FC4C61A8211E6A7C4B8B0C03CF35F7CF20DBD52",
            ),
            (
                "03072783FAAB9549002B4F13140B88132D1C75B3886C",
                "57E8A78E842BF4ACD5C315AA0569DB1703541D96",
            ),
            (
                "03067E3AEA3510D69E8EDD19CB2A703DDC6CF5E56E32",
                "02BD198B83A667A8D908EA1E6F90FD5C6D695DE94F",
            ),
        ],
    );
    assert_eq!(secret, bytes("038359FFD30C0D5FC1E6154F483B73D43E5CF2B503"));
}

fn key_pairs<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) -> [Pair<C>; 4] {
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<C>::new();
    generator
        .init(EcKeyGenerationParams::new(g, &mut rng))
        .unwrap();
    core::array::from_fn(|_| generator.generate_key_pair().unwrap())
}

fn random_parties_agree<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    let [u1, u2, v1, v2] = key_pairs::<C>(g);
    let secret = agree((&u1, &u2), (&v1, &v2)).unwrap();
    assert_eq!(secret, agree((&v1, &v2), (&u1, &u2)).unwrap());

    // 提供的臨時公鑰與省略時算出的相同，結果也相同。
    let mut agreement = EcMqvBasicAgreement::new();
    agreement
        .init(&MqvPrivateParams::new(u1.1.clone(), u2.1.clone()).with_ephemeral_public_key(u2.0))
        .unwrap();
    let mut with_public = vec![0; agreement.agreement_size()];
    agreement
        .calculate_agreement(&MqvPublicParams::new(v1.0, v2.0), &mut with_public)
        .unwrap();
    assert_eq!(with_public, secret);
}

#[test]
fn random_parties_agree_on_prime_and_binary_curves() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    random_parties_agree::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));
    let curve = SECT283K1.ct_curve();
    random_parties_agree::<&F2mCtCurve>(SECT283K1.ct_generator(&curve));
}

#[test]
fn errors_are_reported() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let other_field = SECP256K1.field();
    let other_curve = SECP256K1.ct_curve(&other_field);
    let [u1, u2, v1, v2] = key_pairs::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));
    let [w1, w2, ..] = key_pairs::<&FpCtCurve<'_>>(SECP256K1.ct_generator(&other_curve));
    let public = MqvPublicParams::new(v1.0.clone(), v2.0.clone());

    let uninitialized = EcMqvBasicAgreement::new();
    assert_eq!(
        uninitialized.calculate_agreement(&public, &mut [0; 32]),
        Err(EcMqvError::NotInitialized)
    );

    let mut agreement = EcMqvBasicAgreement::new();
    assert_eq!(
        agreement.init(&MqvPrivateParams::new(u1.1.clone(), w2.1.clone())),
        Err(EcMqvError::DomainMismatch)
    );
    assert_eq!(
        agreement.init(
            &MqvPrivateParams::new(u1.1.clone(), u2.1.clone())
                .with_ephemeral_public_key(w2.0.clone())
        ),
        Err(EcMqvError::DomainMismatch)
    );

    agreement
        .init(&MqvPrivateParams::new(u1.1.clone(), u2.1.clone()))
        .unwrap();
    for other in [
        MqvPublicParams::new(w1.0.clone(), v2.0.clone()),
        MqvPublicParams::new(v1.0.clone(), w2.0.clone()),
    ] {
        assert_eq!(
            agreement.calculate_agreement(&other, &mut [0; 32]),
            Err(EcMqvError::DomainMismatch)
        );
    }
    assert_eq!(
        agreement.calculate_agreement(&public, &mut [0; 31]),
        Err(EcMqvError::BufferTooSmall)
    );
}
