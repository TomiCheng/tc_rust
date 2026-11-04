#![cfg(feature = "x25519")]

// X25519 in the agreement table, found by its name and by id-X25519 as in Bouncy Castle, and the
// agreement it gives: the secret of RFC 7748, and what init and calculate refuse
use std::sync::LazyLock;

use tc_algo::{
    Agreement, AgreementInit, AgreementPeer, Algo, AnyAgreement, AnyAgreementParams, AnyPrivateKey,
    AnyPublicKey, ErrorKind,
};
use tc_asn1::Asn1Oid;
use tc_cfrg_curves::{X25519PrivateKey, X25519PublicKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

// RFC 7748, section 6.1
const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

fn hex32(text: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

fn private(k: &str) -> AnyAgreementParams {
    AnyPrivateKey::X25519(X25519PrivateKey::new(hex32(k))).into()
}

fn public(u: [u8; 32]) -> AgreementPeer {
    AnyPublicKey::X25519(X25519PublicKey::new(u)).into()
}

fn initialized(params: &AnyAgreementParams) -> AnyAgreement {
    let mut x25519 = ALGO.agreement().get_by_name("X25519").unwrap();
    x25519.init(params).unwrap();
    x25519
}

#[test]
fn x25519_is_found_by_its_name_in_any_case_and_by_its_oid() {
    for name in ["X25519", "x25519", "1.3.101.110"] {
        let x25519 = ALGO.agreement().get_by_name(name).unwrap();
        assert_eq!(x25519.entry().name(), "X25519", "{name}");
    }
    let oid: Asn1Oid = "1.3.101.110".parse().unwrap();
    assert_eq!(
        ALGO.agreement().get_by_oid(&oid).unwrap().entry().name(),
        "X25519"
    );
}

#[test]
fn the_entry_shows_its_name_and_its_oid() {
    let entry = ALGO
        .agreement()
        .algorithms()
        .find(|entry| entry.name() == "X25519")
        .unwrap();
    assert_eq!(entry.to_string(), "X25519  [id-X25519]");
}

#[test]
fn both_parties_reach_the_secret_of_rfc_7748() {
    let alice = ALGO.agreement().calculate(
        "X25519",
        &private(ALICE_PRIVATE),
        &public(hex32(BOB_PUBLIC)),
    );
    let bob = ALGO.agreement().calculate(
        "X25519",
        &private(BOB_PRIVATE),
        &public(hex32(ALICE_PUBLIC)),
    );
    assert_eq!(alice.unwrap().as_bytes(), hex32(SHARED));
    assert_eq!(bob.unwrap().as_bytes(), hex32(SHARED));
}

#[test]
fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
    let mut x25519 = ALGO.agreement().get_by_name("X25519").unwrap();
    AgreementInit::init(&mut x25519, &private(ALICE_PRIVATE)).unwrap();
    assert_eq!(x25519.agreement_size(), 32);
    let mut output = [0; 32];
    x25519
        .calculate_agreement(&public(hex32(BOB_PUBLIC)), &mut output)
        .unwrap();
    assert_eq!(output, hex32(SHARED));
    let error = x25519
        .calculate_agreement(&public(hex32(BOB_PUBLIC)), &mut [0; 31])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

// u = 0 and u = 1 have small order, so the secret would be all zeros
#[test]
fn a_public_key_of_small_order_is_refused() {
    let x25519 = initialized(&private(ALICE_PRIVATE));
    let mut one = [0; 32];
    one[0] = 1;
    for u in [[0; 32], one] {
        let error = x25519.calculate(&public(u)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams, "{u:?}");
    }
}

#[test]
fn x25519_refuses_user_keying_material_and_an_ephemeral_key() {
    let mut x25519 = ALGO.agreement().get_by_name("X25519").unwrap();
    let error = x25519
        .init(&private(ALICE_PRIVATE).with_ukm(vec![1, 2, 3]))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let x25519 = initialized(&private(ALICE_PRIVATE));
    let ephemeral = AnyPublicKey::X25519(X25519PublicKey::new(hex32(BOB_PUBLIC)));
    let peer = public(hex32(BOB_PUBLIC)).with_ephemeral(ephemeral);
    let error = x25519.calculate(&peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[cfg(feature = "ed25519")]
#[test]
fn an_ed25519_key_is_refused_on_either_side() {
    use tc_cfrg_curves::Ed25519PrivateKey;

    let ed25519 = Ed25519PrivateKey::new(hex32(ALICE_PRIVATE));
    let ed25519_public = ed25519.generate_public_key();
    let mut x25519 = ALGO.agreement().get_by_name("X25519").unwrap();
    let error = x25519
        .init(&AnyPrivateKey::Ed25519(ed25519).into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let x25519 = initialized(&private(ALICE_PRIVATE));
    let error = x25519
        .calculate(&AnyPublicKey::Ed25519(ed25519_public).into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn calculating_before_init_is_not_initialized() {
    let x25519 = ALGO.agreement().get_by_name("X25519").unwrap();
    let error = x25519.calculate(&public(hex32(BOB_PUBLIC))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
    let error = x25519
        .calculate_agreement(&public(hex32(BOB_PUBLIC)), &mut [0; 32])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn a_failed_init_leaves_no_earlier_key_behind() {
    let mut x25519 = initialized(&private(ALICE_PRIVATE));
    x25519
        .init(&private(ALICE_PRIVATE).with_ukm(vec![1]))
        .unwrap_err();
    let error = x25519.calculate(&public(hex32(BOB_PUBLIC))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn debug_shows_the_name_and_never_the_key_or_the_secret() {
    let x25519 = initialized(&private(ALICE_PRIVATE));
    assert_eq!(
        format!("{x25519:?}"),
        "AnyAgreement { name: \"X25519\", .. }"
    );
    let secret = x25519.calculate(&public(hex32(BOB_PUBLIC))).unwrap();
    assert_eq!(format!("{secret:?}"), "SharedSecret { len: 32, .. }");
}
