#![cfg(feature = "ecvko")]

// GOST VKO in the agreement table: ECGOST3410-2012-256, ECGOST3410-2012-512 and, with gost3411,
// ECGOST3410, found by their names and OIDs as in Bouncy Castle, and the agreements they give:
// RFC 7836's example 7, and what init and calculate refuse
use std::sync::LazyLock;

use std::sync::OnceLock;
use tc_algo::{
    Agreement, AgreementInit, AgreementPeer, Algo, AnyAgreement, AnyAgreementParams,
    AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey, EcCurve, ErrorKind,
};

use tc_asn1::Asn1Oid;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETA;
use tc_fp_curve::{FpCtCurve, FpField};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

// RFC 7836, example 7
const UKM: [u8; 8] = [0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27];
const SECRET: &str = "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 7836 writes its integers little-endian
fn little_endian(hex: &str) -> PaddedBigUint {
    let mut bytes = bytes(hex);
    bytes.reverse();
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes).unwrap()
}

// A key points into its curve, so the curve has to live for the whole program
fn curve() -> &'static FpCtCurve<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = TC26_GOST_3410_12_512_PARAMSETA;
    let field = FIELD.get_or_init(|| named.field());
    CURVE.get_or_init(|| named.ct_curve(field))
}

// One party of example 7 on 512 paramSetA: its params with the UKM, and its public key as the
// other party's peer
fn party(d: &str, x: &str, y: &str) -> (AnyAgreementParams, AgreementPeer) {
    let g = TC26_GOST_3410_12_512_PARAMSETA.ct_generator(curve());
    let q = curve()
        .create_point(&little_endian(x), &little_endian(y))
        .unwrap();
    let private = EcPrivateKey::new(g.clone(), little_endian(d)).unwrap();
    let public = EcPublicKey::new(g, &q).unwrap();
    let params = AnyAgreementParams::new(AnyPrivateKey::Ec(AnyEcPrivateKey::GostTc26ParamSet512A(
        Box::new(private),
    )))
    .with_ukm(UKM.to_vec());
    let peer = AgreementPeer::new(AnyPublicKey::Ec(AnyEcPublicKey::GostTc26ParamSet512A(
        Box::new(public),
    )));
    (params, peer)
}

fn alice() -> (AnyAgreementParams, AgreementPeer) {
    party(
        "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667",
        "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7",
        "914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a",
    )
}

fn bob() -> (AnyAgreementParams, AgreementPeer) {
    party(
        "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db",
        "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651",
        "04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79",
    )
}

fn key_pair(curve: EcCurve) -> (AnyPublicKey, AnyPrivateKey) {
    let mut generator = ALGO.key_pair_generator().get_by_name("EC").unwrap();
    generator.init(curve).unwrap();
    let pair = generator.generate().unwrap();
    (pair.public, pair.private)
}

fn initialized(name: &str, params: &AnyAgreementParams) -> AnyAgreement {
    let mut agreement = ALGO.agreement().get_by_name(name).unwrap();
    agreement.init(params).unwrap();
    agreement
}

#[test]
fn the_2012_agreements_are_found_by_their_names_and_oids() {
    for (name, canonical) in [
        ("ECGOST3410-2012-256", "ECGOST3410-2012-256"),
        ("ecgost3410-2012-256", "ECGOST3410-2012-256"),
        ("1.2.643.7.1.1.6.1", "ECGOST3410-2012-256"),
        ("1.2.643.7.1.1.1.1", "ECGOST3410-2012-256"),
        ("ECGOST3410-2012-512", "ECGOST3410-2012-512"),
        ("1.2.643.7.1.1.6.2", "ECGOST3410-2012-512"),
        ("1.2.643.7.1.1.1.2", "ECGOST3410-2012-512"),
    ] {
        let agreement = ALGO.agreement().get_by_name(name).unwrap();
        assert_eq!(agreement.entry().name(), canonical, "{name}");
    }
    let oid: Asn1Oid = "1.2.643.7.1.1.6.2".parse().unwrap();
    let agreement = ALGO.agreement().get_by_oid(&oid).unwrap();
    assert_eq!(agreement.entry().name(), "ECGOST3410-2012-512");
}

// ECGOST3410 hashes with GOST R 34.11-94, which ecvko does not turn on
#[cfg(feature = "gost3411")]
#[test]
fn the_2001_agreement_is_found_by_its_name_alias_and_oids() {
    for name in [
        "ECGOST3410",
        "GOST-3410-2001",
        "1.2.643.2.2.19",
        "1.2.643.2.2.96",
    ] {
        let agreement = ALGO.agreement().get_by_name(name).unwrap();
        assert_eq!(agreement.entry().name(), "ECGOST3410", "{name}");
    }
}

#[cfg(not(feature = "gost3411"))]
#[test]
fn without_gost3411_the_2001_agreement_is_unknown() {
    let error = ALGO.agreement().get_by_name("ECGOST3410").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
}

#[test]
fn both_parties_reach_the_secret_of_rfc_7836_example_7() {
    let ((alice, alice_peer), (bob, bob_peer)) = (alice(), bob());
    let alice_secret = ALGO
        .agreement()
        .calculate("ECGOST3410-2012-256", &alice, &bob_peer)
        .unwrap();
    let bob_secret = ALGO
        .agreement()
        .calculate("ECGOST3410-2012-256", &bob, &alice_peer)
        .unwrap();
    assert_eq!(alice_secret.as_bytes(), bytes(SECRET));
    assert_eq!(bob_secret.as_bytes(), bytes(SECRET));
}

#[test]
fn both_parties_agree_on_a_secret_as_long_as_the_hash() {
    let mut cases = vec![
        ("ECGOST3410-2012-256", EcCurve::GostTc26ParamSet256A, 32),
        ("ECGOST3410-2012-512", EcCurve::GostTc26ParamSet512C, 64),
    ];
    if cfg!(feature = "gost3411") {
        cases.push(("ECGOST3410", EcCurve::GostCryptoProA, 32));
    }
    for (name, curve, size) in cases {
        let (alice_public, alice_private) = key_pair(curve);
        let (bob_public, bob_private) = key_pair(curve);
        let alice = AnyAgreementParams::new(alice_private).with_ukm(UKM.to_vec());
        let bob = AnyAgreementParams::new(bob_private).with_ukm(UKM.to_vec());
        let alice_secret = ALGO
            .agreement()
            .calculate(name, &alice, &bob_public.into())
            .unwrap();
        let bob_secret = ALGO
            .agreement()
            .calculate(name, &bob, &alice_public.into())
            .unwrap();
        assert_eq!(alice_secret.as_bytes().len(), size, "{name}");
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes(), "{name}");
    }
}

#[test]
fn another_ukm_gives_another_secret() {
    let ((alice, _), (_, bob_peer)) = (alice(), bob());
    let other = AnyAgreementParams::new(alice.key().clone()).with_ukm(vec![1; 8]);
    let secret = ALGO
        .agreement()
        .calculate("ECGOST3410-2012-256", &other, &bob_peer)
        .unwrap();
    assert_ne!(secret.as_bytes(), bytes(SECRET));
}

#[test]
fn the_ukm_is_required_and_a_ukm_of_zero_is_refused() {
    let ((alice, _), (_, bob_peer)) = (alice(), bob());
    let mut vko = ALGO.agreement().get_by_name("ECGOST3410-2012-256").unwrap();
    let error = vko
        .init(&AnyAgreementParams::new(alice.key().clone()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let zero = AnyAgreementParams::new(alice.key().clone()).with_ukm(vec![0; 8]);
    let error = initialized("ECGOST3410-2012-256", &zero)
        .calculate(&bob_peer)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn an_ephemeral_key_of_either_party_is_refused() {
    let ((alice, alice_peer), (_, bob_peer)) = (alice(), bob());
    let mut vko = ALGO.agreement().get_by_name("ECGOST3410-2012-256").unwrap();
    let error = vko
        .init(&alice.clone().with_ephemeral(alice.key().clone()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let peer = bob_peer.with_ephemeral(alice_peer.key().clone());
    let error = initialized("ECGOST3410-2012-256", &alice)
        .calculate(&peer)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn a_public_key_on_another_curve_is_refused() {
    let (alice, _) = alice();
    let (other, _) = key_pair(EcCurve::GostTc26ParamSet512B);
    let error = initialized("ECGOST3410-2012-512", &alice)
        .calculate(&other.into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
    let ((alice, _), (_, bob_peer)) = (alice(), bob());
    let mut vko = ALGO.agreement().get_by_name("ECGOST3410-2012-256").unwrap();
    AgreementInit::init(&mut vko, &alice).unwrap();
    assert_eq!(vko.agreement_size(), 32);
    let mut output = [0; 32];
    vko.calculate_agreement(&bob_peer, &mut output).unwrap();
    assert_eq!(output.to_vec(), bytes(SECRET));
    let error = vko
        .calculate_agreement(&bob_peer, &mut [0; 31])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[test]
fn calculating_before_init_is_not_initialized() {
    let (_, bob_peer) = bob();
    let vko = ALGO.agreement().get_by_name("ECGOST3410-2012-512").unwrap();
    let error = vko.calculate(&bob_peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn debug_shows_the_name_and_never_the_key_or_the_secret() {
    let ((alice, _), (_, bob_peer)) = (alice(), bob());
    let vko = initialized("ECGOST3410-2012-512", &alice);
    assert_eq!(
        format!("{vko:?}"),
        "AnyAgreement { name: \"ECGOST3410-2012-512\", .. }"
    );
    let secret = vko.calculate(&bob_peer).unwrap();
    assert_eq!(format!("{secret:?}"), "SharedSecret { len: 64, .. }");
}

#[test]
fn an_agreement_can_move_to_another_thread() {
    fn send<T: Send>(_: T) {}
    let (alice, _) = alice();
    send(initialized("ECGOST3410-2012-256", &alice));
}
