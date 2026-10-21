use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator, RandomDsaKCalculator};
use tc_ec_core_v2::Curve;
use tc_ec_core_v2::multiplier::CombCt;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdsa_v2::{EcdsaError, EcdsaSigner};
use tc_f2m_curve_v2::F2mCtCurve;
use tc_f2m_curve_v2::named_curves::{SECT163R2, SECT233K1};
use tc_fp_curve_v2::FpCtCurve;
use tc_fp_curve_v2::named_curves::SECP256R1;
use tc_sha::Sha256Digest;

fn integer(text: &str) -> PaddedBigUint {
    let text = format!("{}{text}", "0".repeat(text.len() % 2));
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}

fn sha256(message: &[u8]) -> Vec<u8> {
    let mut digest = Sha256Digest::new();
    digest.update(message);
    let mut hash = vec![0; 32];
    digest.do_final(&mut hash);
    hash
}

fn keys<C: Curve<Scalar = PaddedBigUint>>(
    g: C::Point,
    d: PaddedBigUint,
) -> (EcPrivateKey<C>, EcPublicKey<C>) {
    let q = C::multiply(&g, &d);
    let public_key = EcPublicKey::new(g.clone(), &q).unwrap();
    (EcPrivateKey::new(g, d).unwrap(), public_key)
}

// Signs "sample" with RFC 6979's k and SHA-256, as the RFC's appendix does, then verifies the
// signature, and turns it down for another message.
fn rfc_6979_signature<C: Curve<Scalar = PaddedBigUint>>(g: C::Point, x: &str, r: &str, s: &str) {
    let (private_key, public_key) = keys::<C>(g, integer(x));
    let hash = sha256(b"sample");

    let mut signer = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
    signer.init(&private_key).unwrap();
    let (r_, s_) = signer.generate_signature(&hash).unwrap();
    assert_eq!((&r_, &s_), (&integer(r), &integer(s)));

    signer.init(&public_key).unwrap();
    assert!(signer.verify_signature(&hash, &r_, &s_).unwrap());
    assert!(!signer.verify_signature(&sha256(b"test"), &r_, &s_).unwrap());
}

// RFC 6979 A.2.5.
#[test]
fn p_256_signs_as_rfc_6979_does() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    rfc_6979_signature::<&FpCtCurve<'_>>(
        SECP256R1.ct_generator(&curve),
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    );
}

// RFC 6979 A.2.5 again, on the Ct comb: G and Q multiply through their own tables.
#[test]
fn a_signer_on_the_comb_signs_as_rfc_6979_does() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let (private_key, public_key) = keys::<&FpCtCurve<'_>>(
        SECP256R1.ct_generator(&curve),
        integer("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
    );
    let hash = sha256(b"sample");

    let mut signer = EcdsaSigner::<_, _, CombCt<&FpCtCurve<'_>>>::with_multiplier(
        HMacDsaKCalculator::new(Sha256Digest::new()),
    );
    signer.init(&private_key).unwrap();
    let (r, s) = signer.generate_signature(&hash).unwrap();
    assert_eq!(
        (&r, &s),
        (
            &integer("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
            &integer("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        )
    );

    signer.init(&public_key).unwrap();
    assert!(signer.verify_signature(&hash, &r, &s).unwrap());
    assert!(!signer.verify_signature(&sha256(b"test"), &r, &s).unwrap());
}

// RFC 6979 A.2.9: a binary curve, with cofactor 4.
#[test]
fn k_233_signs_as_rfc_6979_does() {
    let curve = SECT233K1.ct_curve();
    rfc_6979_signature::<&F2mCtCurve>(
        SECT233K1.ct_generator(&curve),
        "103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0",
        "38AD9C1D2CB29906E7D63C24601AC55736B438FB14F4093D6C32F63A10",
        "647AAD2599C21B6EE89BE7FF957D98F684B7921DE1FD3CC82C079624F4",
    );
}

fn random_signatures_verify<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    let (private_key, public_key) = keys::<C>(g, PaddedBigUint::from(0x1234_5678u32));
    let hash = sha256(b"sample");
    let mut rng = rand::rng();
    let mut signer = EcdsaSigner::new(RandomDsaKCalculator::new(&mut rng));

    signer.init(&private_key).unwrap();
    let first = signer.generate_signature(&hash).unwrap();
    let second = signer.generate_signature(&hash).unwrap();
    assert_ne!(first, second);

    signer.init(&public_key).unwrap();
    for (r, s) in [first, second] {
        assert!(signer.verify_signature(&hash, &r, &s).unwrap());
    }
}

#[test]
fn random_signatures_of_one_message_differ_and_both_verify() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    random_signatures_verify::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));

    let curve = SECT163R2.ct_curve();
    random_signatures_verify::<&F2mCtCurve>(SECT163R2.ct_generator(&curve));
}

#[test]
fn a_signer_refuses_the_wrong_key_and_turns_down_r_or_s_out_of_range() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let (private_key, public_key) =
        keys::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve), PaddedBigUint::from(7u8));
    let hash = sha256(b"sample");
    let one = PaddedBigUint::from(1u8);

    let mut signer = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
    assert_eq!(
        signer.generate_signature(&hash),
        Err(EcdsaError::NotInitialized)
    );
    assert_eq!(
        signer.verify_signature(&hash, &one, &one),
        Err(EcdsaError::NotInitialized)
    );

    signer.init(&private_key).unwrap();
    assert_eq!(signer.order(), curve.order().unwrap());
    assert_eq!(
        signer.verify_signature(&hash, &one, &one),
        Err(EcdsaError::NotForVerifying)
    );

    signer.init(&public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&hash),
        Err(EcdsaError::NotForSigning)
    );
    let n = signer.order().clone();
    let zero = PaddedBigUint::from(0u8);
    for (r, s) in [(&zero, &one), (&one, &zero), (&n, &one), (&one, &n)] {
        assert!(!signer.verify_signature(&hash, r, s).unwrap());
    }
}
