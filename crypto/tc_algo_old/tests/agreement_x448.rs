#![cfg(feature = "x448")]

// X448 in the agreement table, found by its name and by id-X448 as in Bouncy Castle, and the
// agreement it gives: the secret of RFC 7748, and what init and calculate refuse
use std::sync::LazyLock;

use tc_algo_old::{
    Agreement, AgreementInit, AgreementPeer, Algo, AnyAgreement, AnyAgreementParams, AnyPrivateKey,
    AnyPublicKey, ErrorKind,
};
use tc_asn1::Asn1Oid;
use tc_cfrg_curves::{X448PrivateKey, X448PublicKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

// RFC 7748, section 6.2
const ALICE_PRIVATE: &str = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
const ALICE_PUBLIC: &str = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
const BOB_PRIVATE: &str = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
const BOB_PUBLIC: &str = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
const SHARED: &str = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

fn hex56(text: &str) -> [u8; 56] {
    let mut bytes = [0; 56];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

fn private(k: &str) -> AnyAgreementParams {
    AnyPrivateKey::X448(X448PrivateKey::new(hex56(k))).into()
}

fn public(u: [u8; 56]) -> AgreementPeer {
    AnyPublicKey::X448(X448PublicKey::new(u)).into()
}

fn initialized(params: &AnyAgreementParams) -> AnyAgreement {
    let mut x448 = ALGO.agreement().get_by_name("X448").unwrap();
    x448.init(params).unwrap();
    x448
}

#[test]
fn x448_is_found_by_its_name_in_any_case_and_by_its_oid() {
    for name in ["X448", "x448", "1.3.101.111"] {
        let x448 = ALGO.agreement().get_by_name(name).unwrap();
        assert_eq!(x448.entry().name(), "X448", "{name}");
    }
    let oid: Asn1Oid = "1.3.101.111".parse().unwrap();
    assert_eq!(
        ALGO.agreement().get_by_oid(&oid).unwrap().entry().name(),
        "X448"
    );
}

#[test]
fn the_entry_shows_its_name_and_its_oid() {
    let entry = ALGO
        .agreement()
        .algorithms()
        .find(|entry| entry.name() == "X448")
        .unwrap();
    assert_eq!(entry.to_string(), "X448  [id-X448]");
}

#[test]
fn both_parties_reach_the_secret_of_rfc_7748() {
    let alice =
        ALGO.agreement()
            .calculate("X448", &private(ALICE_PRIVATE), &public(hex56(BOB_PUBLIC)));
    let bob =
        ALGO.agreement()
            .calculate("X448", &private(BOB_PRIVATE), &public(hex56(ALICE_PUBLIC)));
    assert_eq!(alice.unwrap().as_bytes(), hex56(SHARED));
    assert_eq!(bob.unwrap().as_bytes(), hex56(SHARED));
}

#[test]
fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
    let mut x448 = ALGO.agreement().get_by_name("X448").unwrap();
    AgreementInit::init(&mut x448, &private(ALICE_PRIVATE)).unwrap();
    assert_eq!(x448.agreement_size(), 56);
    let mut output = [0; 56];
    x448.calculate_agreement(&public(hex56(BOB_PUBLIC)), &mut output)
        .unwrap();
    assert_eq!(output, hex56(SHARED));
    let error = x448
        .calculate_agreement(&public(hex56(BOB_PUBLIC)), &mut [0; 55])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

// u = 0 and u = 1 have small order, so the secret would be all zeros
#[test]
fn a_public_key_of_small_order_is_refused() {
    let x448 = initialized(&private(ALICE_PRIVATE));
    let mut one = [0; 56];
    one[0] = 1;
    for u in [[0; 56], one] {
        let error = x448.calculate(&public(u)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams, "{u:?}");
    }
}

#[test]
fn x448_refuses_user_keying_material_and_an_ephemeral_key_of_either_party() {
    let mut x448 = ALGO.agreement().get_by_name("X448").unwrap();
    let error = x448
        .init(&private(ALICE_PRIVATE).with_ukm(vec![1, 2, 3]))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
    let alice = private(ALICE_PRIVATE);
    let error = x448
        .init(&alice.clone().with_ephemeral(alice.key().clone()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let x448 = initialized(&private(ALICE_PRIVATE));
    let ephemeral = AnyPublicKey::X448(X448PublicKey::new(hex56(BOB_PUBLIC)));
    let peer = public(hex56(BOB_PUBLIC)).with_ephemeral(ephemeral);
    let error = x448.calculate(&peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[cfg(feature = "x25519")]
#[test]
fn an_x25519_key_is_refused_on_either_side() {
    use tc_cfrg_curves::X25519PrivateKey;

    let x25519 = X25519PrivateKey::new([7; 32]);
    let x25519_public = x25519.generate_public_key();
    let mut x448 = ALGO.agreement().get_by_name("X448").unwrap();
    let error = x448
        .init(&AnyPrivateKey::X25519(x25519).into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let x448 = initialized(&private(ALICE_PRIVATE));
    let error = x448
        .calculate(&AnyPublicKey::X25519(x25519_public).into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn calculating_before_init_is_not_initialized() {
    let x448 = ALGO.agreement().get_by_name("X448").unwrap();
    let error = x448.calculate(&public(hex56(BOB_PUBLIC))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
    let error = x448
        .calculate_agreement(&public(hex56(BOB_PUBLIC)), &mut [0; 56])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn a_failed_init_leaves_no_earlier_key_behind() {
    let mut x448 = initialized(&private(ALICE_PRIVATE));
    x448.init(&private(ALICE_PRIVATE).with_ukm(vec![1]))
        .unwrap_err();
    let error = x448.calculate(&public(hex56(BOB_PUBLIC))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn debug_shows_the_name_and_never_the_key_or_the_secret() {
    let x448 = initialized(&private(ALICE_PRIVATE));
    assert_eq!(format!("{x448:?}"), "AnyAgreement { name: \"X448\", .. }");
    let secret = x448.calculate(&public(hex56(BOB_PUBLIC))).unwrap();
    assert_eq!(format!("{secret:?}"), "SharedSecret { len: 56, .. }");
}
