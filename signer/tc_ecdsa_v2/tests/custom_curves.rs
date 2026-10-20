use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
use tc_ec_core_v2::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdsa_v2::EcdsaSigner;
use tc_f2m_curve_v2::F2mCtCurve;
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R2};
use tc_f2m_custom_v2::{SecT163FieldElement, SecTCtCurve, SecTVarCurve};
use tc_sha::Sha256Digest;

type Ct<'a> = &'a SecTCtCurve<SecT163FieldElement>;
type Var<'a> = &'a SecTVarCurve<SecT163FieldElement>;

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
