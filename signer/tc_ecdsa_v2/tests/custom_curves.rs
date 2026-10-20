use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
use tc_ec_core_v2::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdsa_v2::EcdsaSigner;
use tc_f2m_curve_v2::F2mCtCurve;
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_custom_v2::named_curves::{
    SECT163K1, SECT163R2, SECT193R1, SECT233K1, SECT239K1, SECT283K1, SECT409R1, SECT571K1,
};
use tc_f2m_custom_v2::{
    SecT163FieldElement, SecT193FieldElement, SecT233FieldElement, SecT239FieldElement,
    SecT283FieldElement, SecT409FieldElement, SecT571FieldElement, SecTCtCurve, SecTVarCurve,
};
use tc_sha::Sha256Digest;

type Ct<'a> = &'a SecTCtCurve<SecT163FieldElement>;
type Var<'a> = &'a SecTVarCurve<SecT163FieldElement>;
type Ct233<'a> = &'a SecTCtCurve<SecT233FieldElement>;
type Var233<'a> = &'a SecTVarCurve<SecT233FieldElement>;

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

fn sign<C: Curve<Scalar = PaddedBigUint>>(
    g: C::Point,
    d: &PaddedBigUint,
    hash: &[u8],
) -> (PaddedBigUint, PaddedBigUint) {
    let mut signer = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
    signer
        .init(&EcPrivateKey::<C>::new(g, d.clone()).unwrap())
        .unwrap();
    signer.generate_signature(hash).unwrap()
}

fn verify<C: Curve<Scalar = PaddedBigUint>>(
    g: C::Point,
    d: &PaddedBigUint,
    hash: &[u8],
    (r, s): &(PaddedBigUint, PaddedBigUint),
) -> bool {
    let q = C::multiply(&g, d);
    let mut signer = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
    signer.init(&EcPublicKey::<C>::new(g, &q).unwrap()).unwrap();
    signer.verify_signature(hash, r, s).unwrap()
}

// RFC 6979 A.2.8: K-163, SHA-256, "sample". Signed on the constant-time curve and verified
// on the variable-time one.
#[test]
fn k_163_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECT163K1.ct_curve(), SECT163K1.var_curve());
    let d = integer("09A4D6792295A7F730FC3F2B49CBC0F62E862272F");
    let hash = sha256(b"sample");

    let signature = sign::<Ct<'_>>(SECT163K1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer("113A63990598A3828C407C0F4D2438D990DF99A7F"),
            integer("1313A2E03F5412DDB296A22E2C455335545672D9F"),
        )
    );
    assert!(verify::<Var<'_>>(
        SECT163K1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
    assert!(!verify::<Var<'_>>(
        SECT163K1.var_generator(&var),
        &d,
        &sha256(b"test"),
        &signature
    ));
}

// The same key, message and deterministic k give the same signature on the specialized
// and the generic B-163, and each verifies the other's.
#[test]
fn b_163_signs_as_the_generic_curve_does() {
    let (ct, var) = (SECT163R2.ct_curve(), SECT163R2.var_curve());
    let reference = generic::SECT163R2.ct_curve();
    let d = integer("0123456789ABCDEF0123456789ABCDEF012345678");
    let hash = sha256(b"sample");

    let signature = sign::<Ct<'_>>(SECT163R2.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT163R2.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    assert!(verify::<Var<'_>>(
        SECT163R2.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
    assert!(verify::<&F2mCtCurve>(
        generic::SECT163R2.ct_generator(&reference),
        &d,
        &hash,
        &signature
    ));
}

// RFC 6979 A.2.9: K-233, SHA-256, "sample"; a cofactor of 4 and a four-limb field.
#[test]
fn k_233_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECT233K1.ct_curve(), SECT233K1.var_curve());
    let d = integer("103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0");
    let hash = sha256(b"sample");

    let signature = sign::<Ct233<'_>>(SECT233K1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer("38AD9C1D2CB29906E7D63C24601AC55736B438FB14F4093D6C32F63A10"),
            integer("647AAD2599C21B6EE89BE7FF957D98F684B7921DE1FD3CC82C079624F4"),
        )
    );
    assert!(verify::<Var233<'_>>(
        SECT233K1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// On a curve of each further specialized field, the same key, message and deterministic k give
// the generic curve's signature, which the Var curve verifies.
#[test]
fn the_other_fields_sign_as_the_generic_curves_do() {
    let d = integer("0123456789ABCDEF0123456789ABCDEF012345678");
    let hash = sha256(b"sample");

    let (ct, var, reference) = (
        SECT193R1.ct_curve(),
        SECT193R1.var_curve(),
        generic::SECT193R1.ct_curve(),
    );
    let signature =
        sign::<&SecTCtCurve<SecT193FieldElement>>(SECT193R1.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT193R1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    let g = SECT193R1.var_generator(&var);
    assert!(verify::<&SecTVarCurve<SecT193FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var, reference) = (
        SECT239K1.ct_curve(),
        SECT239K1.var_curve(),
        generic::SECT239K1.ct_curve(),
    );
    let signature =
        sign::<&SecTCtCurve<SecT239FieldElement>>(SECT239K1.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT239K1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    let g = SECT239K1.var_generator(&var);
    assert!(verify::<&SecTVarCurve<SecT239FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var, reference) = (
        SECT283K1.ct_curve(),
        SECT283K1.var_curve(),
        generic::SECT283K1.ct_curve(),
    );
    let signature =
        sign::<&SecTCtCurve<SecT283FieldElement>>(SECT283K1.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT283K1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    let g = SECT283K1.var_generator(&var);
    assert!(verify::<&SecTVarCurve<SecT283FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var, reference) = (
        SECT409R1.ct_curve(),
        SECT409R1.var_curve(),
        generic::SECT409R1.ct_curve(),
    );
    let signature =
        sign::<&SecTCtCurve<SecT409FieldElement>>(SECT409R1.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT409R1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    let g = SECT409R1.var_generator(&var);
    assert!(verify::<&SecTVarCurve<SecT409FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var, reference) = (
        SECT571K1.ct_curve(),
        SECT571K1.var_curve(),
        generic::SECT571K1.ct_curve(),
    );
    let signature =
        sign::<&SecTCtCurve<SecT571FieldElement>>(SECT571K1.ct_generator(&ct), &d, &hash);
    let expected = sign::<&F2mCtCurve>(generic::SECT571K1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    let g = SECT571K1.var_generator(&var);
    assert!(verify::<&SecTVarCurve<SecT571FieldElement>>(
        g, &d, &hash, &signature
    ));
}
