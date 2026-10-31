//! `EcdhcBasicAgreement`：雙方一致；結果是 (h·d)·Q 的 x 座標，h 為 1 時與 ECDH 相同、
//! 否則不同；以及錯誤。

use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_ecdh_v2::{EcdhBasicAgreement, EcdhError, EcdhcBasicAgreement};
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_curve::named_curves::{SECT163K1, SECT233K1};
use tc_fp_curve::FpCtCurve;
use tc_fp_curve::named_curves::{SECP256K1, SECP256R1};
use tc_modular::{ModMul, NonZero};

type Pair<C> = (EcPublicKey<C>, EcPrivateKey<C>);

fn key_pairs<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) -> [Pair<C>; 2] {
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<C>::new();
    generator
        .init(EcKeyGenerationParams::new(g, &mut rng))
        .unwrap();
    [
        generator.generate_key_pair().unwrap(),
        generator.generate_key_pair().unwrap(),
    ]
}

fn ecdhc<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
) -> Result<Vec<u8>, EcdhError> {
    let mut agreement = EcdhcBasicAgreement::new();
    agreement.init(key)?;
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

fn ecdh<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
) -> Vec<u8> {
    let mut agreement = EcdhBasicAgreement::new();
    agreement.init(key).unwrap();
    let mut secret = vec![0; agreement.agreement_size()];
    agreement
        .calculate_agreement(public_key, &mut secret)
        .unwrap();
    secret
}

/// 雙方一致，且等於 (h·d_A)·Q_B 的 x 座標；h 為 1 時與 ECDH 相同，否則不同。
fn the_secret_is_the_cofactor_multiple<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    let [(public_a, private_a), (public_b, private_b)] = key_pairs::<C>(g.clone());
    let secret = ecdhc(&private_a, &public_b).unwrap();
    assert_eq!(secret, ecdhc(&private_b, &public_a).unwrap());

    let curve = g.curve();
    let h = curve.cofactor().unwrap().clone();
    let n = NonZero::new(curve.order().unwrap().clone()).unwrap();
    let shared = C::multiply(public_b.q(), &h.mod_mul(private_a.d(), &n));
    let mut expected = vec![0; secret.len()];
    shared.x().unwrap().encode_to(&mut expected);
    assert_eq!(secret, expected);

    let same_as_ecdh = secret == ecdh(&private_a, &public_b);
    assert_eq!(same_as_ecdh, h == PaddedBigUint::from(1u8));
}

#[test]
fn the_secret_is_x_of_h_d_q_and_matches_ecdh_only_when_h_is_one() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    the_secret_is_the_cofactor_multiple::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));
    // sect163k1 的餘因子是 2，sect233k1 的是 4。
    let curve = SECT163K1.ct_curve();
    the_secret_is_the_cofactor_multiple::<&F2mCtCurve>(SECT163K1.ct_generator(&curve));
    let curve = SECT233K1.ct_curve();
    the_secret_is_the_cofactor_multiple::<&F2mCtCurve>(SECT233K1.ct_generator(&curve));
}

#[test]
fn errors_are_reported() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let other_field = SECP256K1.field();
    let other_curve = SECP256K1.ct_curve(&other_field);
    let [(public_key, private_key), _] =
        key_pairs::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));
    let [(other_public, _), _] = key_pairs::<&FpCtCurve<'_>>(SECP256K1.ct_generator(&other_curve));

    let uninitialized = EcdhcBasicAgreement::new();
    assert_eq!(
        uninitialized.calculate_agreement(&public_key, &mut [0; 32]),
        Err(EcdhError::NotInitialized)
    );
    assert_eq!(
        ecdhc(&private_key, &other_public),
        Err(EcdhError::WrongDomain)
    );
    let mut agreement = EcdhcBasicAgreement::new();
    agreement.init(&private_key).unwrap();
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 31]),
        Err(EcdhError::BufferTooSmall)
    );
}
