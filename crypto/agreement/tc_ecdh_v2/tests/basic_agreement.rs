use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_ecdh_v2::{EcdhBasicAgreement, EcdhError};
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_curve::named_curves::{SECT163R2, SECT283K1};
use tc_fp_curve::FpCtCurve;
use tc_fp_curve::named_curves::{SECP256K1, SECP256R1};
use tc_fp_custom::named_curves as custom;
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve,
};

fn integer(text: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes).unwrap()
}

fn agree<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
) -> Result<Vec<u8>, EcdhError> {
    let mut agreement = EcdhBasicAgreement::new();
    agreement.init(key)?;
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

// Two parties agree, and on the x coordinate of d_A·d_B·G, whatever the cofactor step did.
fn two_parties_agree<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<C>::new();
    generator
        .init(EcKeyGenerationParams::new(g.clone(), &mut rng))
        .unwrap();
    let (public_a, private_a) = generator.generate_key_pair().unwrap();
    let (public_b, private_b) = generator.generate_key_pair().unwrap();

    let secret = agree(&private_a, &public_b).unwrap();
    assert_eq!(secret, agree(&private_b, &public_a).unwrap());

    let shared = C::multiply(public_b.q(), private_a.d());
    let mut expected = vec![0; secret.len()];
    shared.x().unwrap().encode_to(&mut expected);
    assert_eq!(secret, expected);
}

#[test]
fn two_parties_reach_the_same_secret_whatever_the_cofactor() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    two_parties_agree::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));

    let curve = SECT163R2.ct_curve();
    two_parties_agree::<&F2mCtCurve>(SECT163R2.ct_generator(&curve));

    let curve = SECT283K1.ct_curve();
    two_parties_agree::<&F2mCtCurve>(SECT283K1.ct_generator(&curve));
}

// RFC 5903, 8.1: ECDH on P-256.
#[test]
fn p_256_gives_the_shared_secret_of_rfc_5903() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    type Ct<'a> = &'a FpCtCurve<'a>;

    let i = integer("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gr = curve
        .create_point(
            &integer("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"),
            &integer("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"),
        )
        .unwrap();
    let private_key = EcPrivateKey::<Ct<'_>>::new(g.clone(), i).unwrap();
    let public_key = EcPublicKey::<Ct<'_>>::new(g, &gr).unwrap();

    let expected = integer("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");
    assert_eq!(
        agree(&private_key, &public_key).unwrap(),
        ArrayEncoding::<u8>::to_be(&expected)
    );
}

#[test]
fn an_agreement_refuses_to_run_uninitialized_on_another_domain_or_into_a_short_buffer() {
    let field_k1 = SECP256K1.field();
    let k1 = SECP256K1.ct_curve(&field_k1);
    let g_k1 = SECP256K1.ct_generator(&k1);
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let other = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    let h = SECP256R1.ct_generator(&other);
    type Ct<'a> = &'a FpCtCurve<'a>;

    let key = EcPrivateKey::<Ct<'_>>::new(g.clone(), PaddedBigUint::from(7u8)).unwrap();
    let public_key = EcPublicKey::<Ct<'_>>::new(g.clone(), &g.twice()).unwrap();

    let agreement = EcdhBasicAgreement::<Ct<'_>>::new();
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 32]),
        Err(EcdhError::NotInitialized)
    );

    let mut agreement = EcdhBasicAgreement::new();
    agreement.init(&key).unwrap();
    assert_eq!(agreement.agreement_size(), 32);
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 31]),
        Err(EcdhError::BufferTooSmall)
    );

    // The same parameters on a curve built twice are the same domain, as in BC.
    let elsewhere = EcPublicKey::<Ct<'_>>::new(h.clone(), &h.twice()).unwrap();
    assert!(
        agreement
            .calculate_agreement(&elsewhere, &mut [0; 32])
            .is_ok()
    );

    let stranger = EcPublicKey::<Ct<'_>>::new(g_k1.clone(), &g_k1.twice()).unwrap();
    assert_eq!(
        agreement.calculate_agreement(&stranger, &mut [0; 32]),
        Err(EcdhError::WrongDomain)
    );
}

// The specialized prime curves reach the x coordinate of d_A·d_B·G too.
#[test]
fn two_parties_agree_on_the_specialized_prime_curves() {
    let curve = custom::SECP256R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP256R1FieldElement>>(
        custom::SECP256R1.ct_generator(&curve),
    );

    let curve = custom::SECP256K1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP256K1FieldElement>>(
        custom::SECP256K1.ct_generator(&curve),
    );

    let curve = custom::SECP384R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP384R1FieldElement>>(
        custom::SECP384R1.ct_generator(&curve),
    );
}

// RFC 5903, 8.1, on the specialized P-256.
#[test]
fn the_specialized_p_256_gives_the_shared_secret_of_rfc_5903() {
    let curve = custom::SECP256R1.ct_curve();
    let g = custom::SECP256R1.ct_generator(&curve);
    type Ct<'a> = &'a SecPCtCurve<SecP256R1FieldElement>;
    let bytes = |text: &str| ArrayEncoding::<u8>::to_be(&integer(text));

    let i = integer("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gr = curve
        .create_point(
            &bytes("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"),
            &bytes("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"),
        )
        .unwrap();
    let private_key = EcPrivateKey::<Ct<'_>>::new(g.clone(), i).unwrap();
    let public_key = EcPublicKey::<Ct<'_>>::new(g, &gr).unwrap();

    assert_eq!(
        agree(&private_key, &public_key).unwrap(),
        bytes("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
    );
}

// And on the other specialized prime curves, the small ones included.
#[test]
fn two_parties_agree_on_the_other_specialized_prime_curves() {
    let curve = custom::SECP128R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP128R1FieldElement>>(
        custom::SECP128R1.ct_generator(&curve),
    );

    let curve = custom::SECP160K1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP160R2FieldElement>>(
        custom::SECP160K1.ct_generator(&curve),
    );

    let curve = custom::SECP160R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP160R1FieldElement>>(
        custom::SECP160R1.ct_generator(&curve),
    );

    let curve = custom::SECP160R2.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP160R2FieldElement>>(
        custom::SECP160R2.ct_generator(&curve),
    );

    let curve = custom::SECP192K1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP192K1FieldElement>>(
        custom::SECP192K1.ct_generator(&curve),
    );

    let curve = custom::SECP192R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP192R1FieldElement>>(
        custom::SECP192R1.ct_generator(&curve),
    );

    let curve = custom::SECP224K1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP224K1FieldElement>>(
        custom::SECP224K1.ct_generator(&curve),
    );

    let curve = custom::SECP224R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP224R1FieldElement>>(
        custom::SECP224R1.ct_generator(&curve),
    );

    let curve = custom::SECP521R1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SecP521R1FieldElement>>(
        custom::SECP521R1.ct_generator(&curve),
    );

    let curve = custom::SM2P256V1.ct_curve();
    two_parties_agree::<&SecPCtCurve<SM2P256V1FieldElement>>(
        custom::SM2P256V1.ct_generator(&curve),
    );
}
