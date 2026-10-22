use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdsa_v2::EcdsaSigner;
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_curve::named_curves as generic;
use tc_f2m_custom::named_curves::{
    SECT163K1, SECT163R2, SECT193R1, SECT233K1, SECT239K1, SECT283K1, SECT409R1, SECT571K1,
};
use tc_f2m_custom::{
    SecT163FieldElement, SecT193FieldElement, SecT233FieldElement, SecT239FieldElement,
    SecT283FieldElement, SecT409FieldElement, SecT571FieldElement, SecTCtCurve, SecTVarCurve,
};
use tc_fp_curve::named_curves as generic_prime;
use tc_fp_curve::{FpCtCurve, FpField};
use tc_fp_custom::named_curves::{
    SECP128R1, SECP160K1, SECP160R1, SECP160R2, SECP192K1, SECP192R1, SECP224K1, SECP224R1,
    SECP256K1, SECP256R1, SECP384R1, SECP521R1, SM2P256V1,
};
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve, SecPVarCurve,
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

// RFC 6979 A.2.5: P-256, SHA-256, "sample". Signed on the specialized constant-time curve and
// verified on the variable-time one.
#[test]
fn p_256_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECP256R1.ct_curve(), SECP256R1.var_curve());
    let d = integer("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP256R1FieldElement>>(SECP256R1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
            integer("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        )
    );
    let g = SECP256R1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP256R1FieldElement>>(
        g.clone(),
        &d,
        &hash,
        &signature
    ));
    assert!(!verify::<&SecPVarCurve<SecP256R1FieldElement>>(
        g,
        &d,
        &sha256(b"test"),
        &signature
    ));
}

// RFC 6979 A.2.6: P-384 with SHA-256, "sample"; a twelve-limb field.
#[test]
fn p_384_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECP384R1.ct_curve(), SECP384R1.var_curve());
    let d = integer(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
    );
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP384R1FieldElement>>(SECP384R1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer(
                "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
            ),
            integer(
                "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0",
            ),
        )
    );
    assert!(verify::<&SecPVarCurve<SecP384R1FieldElement>>(
        SECP384R1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// secp256k1, which RFC 6979 does not list: the same key, message and deterministic k give
// the generic curve's signature, which the specialized Var curve verifies.
#[test]
fn secp256k1_signs_as_the_generic_curve_does() {
    let (ct, var) = (SECP256K1.ct_curve(), SECP256K1.var_curve());
    let field = generic_prime::SECP256K1.field();
    let reference = generic_prime::SECP256K1.ct_curve(&field);
    let d = integer("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP256K1FieldElement>>(SECP256K1.ct_generator(&ct), &d, &hash);
    let expected =
        sign::<&FpCtCurve<'_>>(generic_prime::SECP256K1.ct_generator(&reference), &d, &hash);
    assert_eq!(signature, expected);
    assert!(verify::<&SecPVarCurve<SecP256K1FieldElement>>(
        SECP256K1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// RFC 6979 A.2.3: P-192, SHA-256, "sample", on the specialized curves.
#[test]
fn secp192r1_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECP192R1.ct_curve(), SECP192R1.var_curve());
    let d = integer("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4");
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP192R1FieldElement>>(SECP192R1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55"),
            integer("CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85")
        )
    );
    assert!(verify::<&SecPVarCurve<SecP192R1FieldElement>>(
        SECP192R1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// RFC 6979 A.2.4: P-224, SHA-256, "sample", on the specialized curves.
#[test]
fn secp224r1_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECP224R1.ct_curve(), SECP224R1.var_curve());
    let d = integer("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1");
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP224R1FieldElement>>(SECP224R1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer("61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA"),
            integer("BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101")
        )
    );
    assert!(verify::<&SecPVarCurve<SecP224R1FieldElement>>(
        SECP224R1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// RFC 6979 A.2.7: P-521, SHA-256, "sample", on the specialized curves.
#[test]
fn secp521r1_signs_as_rfc_6979_does_on_the_specialized_curve() {
    let (ct, var) = (SECP521R1.ct_curve(), SECP521R1.var_curve());
    let d = integer(
        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
    );
    let hash = sha256(b"sample");

    let signature =
        sign::<&SecPCtCurve<SecP521R1FieldElement>>(SECP521R1.ct_generator(&ct), &d, &hash);
    assert_eq!(
        signature,
        (
            integer(
                "1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7"
            ),
            integer(
                "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"
            )
        )
    );
    assert!(verify::<&SecPVarCurve<SecP521R1FieldElement>>(
        SECP521R1.var_generator(&var),
        &d,
        &hash,
        &signature
    ));
}

// A generic curve of these parameters, p, a, b, n, gx and gy, signing with the same key,
// message and deterministic k.
fn generic_signature(
    params: [&str; 6],
    d: &PaddedBigUint,
    hash: &[u8],
) -> (PaddedBigUint, PaddedBigUint) {
    let [p, a, b, n, gx, gy] = params.map(integer);
    let field = FpField::new(p).unwrap();
    let one = Some(PaddedBigUint::from(1u8));
    let curve = FpCtCurve::new(&field, &a, &b, Some(n), one).unwrap();
    sign::<&FpCtCurve<'_>>(curve.create_point(&gx, &gy).unwrap(), d, hash)
}

const SECP128R1_PARAMS: [&str; 6] = [
    "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
    "E87579C11079F43DD824993C2CEE5ED3",
    "FFFFFFFE0000000075A30D1B9038A115",
    "161FF7528B899B2D0C28607CA52C5B86",
    "CF5AC8395BAFEB13C02DA292DDED7A83",
];

const SECP160K1_PARAMS: [&str; 6] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000007",
    "100000000000000000001B8FA16DFAB9ACA16B6B3",
    "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB",
    "938CF935318FDCED6BC28286531733C3F03C4FEE",
];

const SECP160R1_PARAMS: [&str; 6] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
    "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
    "100000000000000000001F4C8F927AED3CA752257",
    "4A96B5688EF573284664698968C38BB913CBFC82",
    "23A628553168947D59DCC912042351377AC5FB32",
];

const SECP160R2_PARAMS: [&str; 6] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
    "B4E134D3FB59EB8BAB57274904664D5AF50388BA",
    "100000000000000000000351EE786A818F3A1A16B",
    "52DCB034293A117E1F4FF11B30F7199D3144CE6D",
    "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
];

const SECP192K1_PARAMS: [&str; 6] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
    "000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000003",
    "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",
    "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",
    "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
];

const SECP224K1_PARAMS: [&str; 6] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
    "00000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000005",
    "10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
    "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
    "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
];

const SM2P256V1_PARAMS: [&str; 6] = [
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
];

// On the other specialized prime fields, which RFC 6979 does not list, the same key, message
// and deterministic k give the generic curve's signature, which the Var curve verifies.
#[test]
fn the_other_prime_fields_sign_as_the_generic_curves_do() {
    let d = integer("0123456789ABCDEF0123456789ABCDEF");
    let hash = sha256(b"sample");

    let (ct, var) = (SECP128R1.ct_curve(), SECP128R1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP128R1FieldElement>>(SECP128R1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP128R1_PARAMS, &d, &hash));
    let g = SECP128R1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP128R1FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SECP160K1.ct_curve(), SECP160K1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP160R2FieldElement>>(SECP160K1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP160K1_PARAMS, &d, &hash));
    let g = SECP160K1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP160R2FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SECP160R1.ct_curve(), SECP160R1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP160R1FieldElement>>(SECP160R1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP160R1_PARAMS, &d, &hash));
    let g = SECP160R1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP160R1FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SECP160R2.ct_curve(), SECP160R2.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP160R2FieldElement>>(SECP160R2.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP160R2_PARAMS, &d, &hash));
    let g = SECP160R2.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP160R2FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SECP192K1.ct_curve(), SECP192K1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP192K1FieldElement>>(SECP192K1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP192K1_PARAMS, &d, &hash));
    let g = SECP192K1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP192K1FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SECP224K1.ct_curve(), SECP224K1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SecP224K1FieldElement>>(SECP224K1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SECP224K1_PARAMS, &d, &hash));
    let g = SECP224K1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SecP224K1FieldElement>>(
        g, &d, &hash, &signature
    ));

    let (ct, var) = (SM2P256V1.ct_curve(), SM2P256V1.var_curve());
    let signature =
        sign::<&SecPCtCurve<SM2P256V1FieldElement>>(SM2P256V1.ct_generator(&ct), &d, &hash);
    assert_eq!(signature, generic_signature(SM2P256V1_PARAMS, &d, &hash));
    let g = SM2P256V1.var_generator(&var);
    assert!(verify::<&SecPVarCurve<SM2P256V1FieldElement>>(
        g, &d, &hash, &signature
    ));
}
