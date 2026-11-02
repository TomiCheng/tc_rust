#![cfg(feature = "ecdh")]

// ECDH and ECDHC in the agreement table, found by their names as in Bouncy Castle and by nothing
// else, and the agreements they give: the secret of RFC 5903, and what init and calculate refuse
use std::sync::OnceLock;

use tc_algo::ErrorKind;
use tc_algo::agreement::{
    self, Agreement, AgreementInit, AgreementPeer, AnyAgreement, AnyAgreementParams,
};
use tc_algo::generate;
use tc_algo::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey, EcCurve};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_fp_custom::{SecP256R1FieldElement, SecPCtCurve, SecPCtPoint};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// A key points into its curve, so the curve has to live for the whole program
fn p256() -> &'static SecPCtCurve<SecP256R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256R1FieldElement>> = OnceLock::new();
    CURVE.get_or_init(|| tc_fp_custom::named_curves::SECP256R1.ct_curve())
}

fn p256_generator() -> SecPCtPoint<'static, SecP256R1FieldElement> {
    tc_fp_custom::named_curves::SECP256R1.ct_generator(p256())
}

fn p256_private(d: &str) -> AnyAgreementParams {
    let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(d)).unwrap();
    let key = EcPrivateKey::new(p256_generator(), d).unwrap();
    AnyPrivateKey::Ec(AnyEcPrivateKey::Secp256r1(Box::new(key))).into()
}

fn p256_public(x: &str, y: &str) -> AgreementPeer {
    let q = p256().create_point(&hex(x), &hex(y)).unwrap();
    let key = EcPublicKey::new(p256_generator(), &q).unwrap();
    AnyPublicKey::Ec(AnyEcPublicKey::Secp256r1(Box::new(key))).into()
}

// RFC 5903, section 8.1: the initiator's private key and the responder's public key
fn rfc_5903_keys() -> (AnyAgreementParams, AgreementPeer) {
    let i = p256_private("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gr = p256_public(
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
    );
    (i, gr)
}

const RFC_5903_SECRET: &str = "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE";

fn key_pair(curve: EcCurve) -> (AnyPublicKey, AnyPrivateKey) {
    let mut generator = generate::key_pair::get_by_name("EC").unwrap();
    generator.init(curve).unwrap();
    let pair = generator.generate().unwrap();
    (pair.public, pair.private)
}

fn initialized(name: &str, params: &AnyAgreementParams) -> AnyAgreement {
    let mut agreement = agreement::get_by_name(name).unwrap();
    agreement.init(params).unwrap();
    agreement
}

#[test]
fn ecdh_and_ecdhc_are_found_by_their_names_and_aliases_in_any_case() {
    for (name, canonical) in [
        ("ECDH", "ECDH"),
        ("ecdh", "ECDH"),
        ("ECDHC", "ECDHC"),
        ("ECCDH", "ECDHC"),
        ("eccdh", "ECDHC"),
    ] {
        let agreement = agreement::get_by_name(name).unwrap();
        assert_eq!(agreement.entry().name(), canonical, "{name}");
    }
}

// The OIDs of ECDH name the schemes with a KDF, which these agreements are not
#[test]
fn neither_has_an_oid_and_a_kdf_scheme_names_neither() {
    for name in ["ECDH", "ECDHC"] {
        let entry = agreement::algorithms()
            .find(|entry| entry.name() == name)
            .unwrap();
        assert!(entry.oids().is_empty());
        assert_eq!(entry.to_string(), name);
    }
    let error = agreement::get_by_name("1.3.132.1.11.1").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
}

#[test]
fn ecdh_on_p_256_gives_the_secret_of_rfc_5903() {
    let (i, gr) = rfc_5903_keys();
    let secret = agreement::calculate("ECDH", &i, &gr).unwrap();
    assert_eq!(secret.as_bytes(), hex(RFC_5903_SECRET));
}

// P-256 has a cofactor of 1
#[test]
fn with_a_cofactor_of_one_ecdhc_gives_what_ecdh_gives() {
    let (i, gr) = rfc_5903_keys();
    let secret = agreement::calculate("ECDHC", &i, &gr).unwrap();
    assert_eq!(secret.as_bytes(), hex(RFC_5903_SECRET));
}

#[test]
fn both_parties_reach_the_same_secret_as_long_as_a_coordinate() {
    for (curve, size) in [
        (EcCurve::Secp256r1, 32),
        (EcCurve::Secp384r1, 48),
        (EcCurve::Secp521r1, 66),
    ] {
        let (alice_public, alice_private) = key_pair(curve);
        let (bob_public, bob_private) = key_pair(curve);
        let alice =
            agreement::calculate("ECDH", &alice_private.into(), &bob_public.into()).unwrap();
        let bob = agreement::calculate("ECDH", &bob_private.into(), &alice_public.into()).unwrap();
        assert_eq!(alice.as_bytes().len(), size, "{curve:?}");
        assert_eq!(alice.as_bytes(), bob.as_bytes(), "{curve:?}");
    }
}

// sect233k1 has a cofactor of 4
#[cfg(feature = "ec-f2m")]
#[test]
fn with_another_cofactor_ecdhc_agrees_on_a_secret_of_its_own() {
    let (alice_public, alice_private) = key_pair(EcCurve::Sect233k1);
    let (bob_public, bob_private) = key_pair(EcCurve::Sect233k1);
    let (alice_private, bob_private) = (alice_private.into(), bob_private.into());
    let (alice_public, bob_public) = (alice_public.into(), bob_public.into());
    let ecdh = agreement::calculate("ECDH", &alice_private, &bob_public).unwrap();
    let alice = agreement::calculate("ECDHC", &alice_private, &bob_public).unwrap();
    let bob = agreement::calculate("ECDHC", &bob_private, &alice_public).unwrap();
    assert_eq!(alice.as_bytes(), bob.as_bytes());
    assert_ne!(alice.as_bytes(), ecdh.as_bytes());
}

#[test]
fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
    let (i, gr) = rfc_5903_keys();
    let mut ecdh = agreement::get_by_name("ECDH").unwrap();
    AgreementInit::init(&mut ecdh, &i).unwrap();
    assert_eq!(ecdh.agreement_size(), 32);
    let mut output = [0; 32];
    ecdh.calculate_agreement(&gr, &mut output).unwrap();
    assert_eq!(output.to_vec(), hex(RFC_5903_SECRET));
    let error = ecdh.calculate_agreement(&gr, &mut [0; 31]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[test]
fn a_public_key_on_another_curve_is_refused() {
    let (i, _) = rfc_5903_keys();
    let (p384, _) = key_pair(EcCurve::Secp384r1);
    for name in ["ECDH", "ECDHC"] {
        let error = initialized(name, &i)
            .calculate(&p384.clone().into())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name}");
    }
}

#[cfg(feature = "x25519")]
#[test]
fn a_key_that_is_not_ec_is_refused_on_either_side() {
    let x25519 = generate::key_pair::generate("X25519").unwrap();
    let mut ecdh = agreement::get_by_name("ECDH").unwrap();
    let error = ecdh.init(&x25519.private.into()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let (i, _) = rfc_5903_keys();
    let error = initialized("ECDH", &i)
        .calculate(&x25519.public.into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn ecdh_refuses_user_keying_material_and_an_ephemeral_key() {
    let (i, gr) = rfc_5903_keys();
    let mut ecdh = agreement::get_by_name("ECDH").unwrap();
    let error = ecdh.init(&i.clone().with_ukm(vec![1, 2, 3])).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let (_, ephemeral) = rfc_5903_keys();
    let peer = gr.with_ephemeral(ephemeral.key().clone());
    let error = initialized("ECDH", &i).calculate(&peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn calculating_before_init_is_not_initialized() {
    let (_, gr) = rfc_5903_keys();
    let ecdh = agreement::get_by_name("ECDH").unwrap();
    let error = ecdh.calculate(&gr).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
    let error = ecdh.calculate_agreement(&gr, &mut [0; 32]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn a_failed_init_leaves_no_earlier_key_behind() {
    let (i, gr) = rfc_5903_keys();
    let mut ecdh = initialized("ECDH", &i);
    ecdh.init(&i.with_ukm(vec![1])).unwrap_err();
    let error = ecdh.calculate(&gr).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn debug_shows_the_name_and_never_the_key_or_the_secret() {
    let (i, gr) = rfc_5903_keys();
    let ecdh = initialized("ECDH", &i);
    assert_eq!(format!("{ecdh:?}"), "AnyAgreement { name: \"ECDH\", .. }");
    let secret = ecdh.calculate(&gr).unwrap();
    assert_eq!(format!("{secret:?}"), "SharedSecret { len: 32, .. }");
}

#[test]
fn an_agreement_can_move_to_another_thread() {
    fn send<T: Send>(_: T) {}
    let (i, _) = rfc_5903_keys();
    send(initialized("ECDHC", &i));
}
