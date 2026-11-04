#![cfg(feature = "ecmqv")]

// ECMQV in the agreement table, found by its name as in Bouncy Castle and by nothing else, and the
// agreement it gives: the GEC 2 vectors of Bouncy Castle's ECTest, and what init and calculate
// refuse
use std::sync::LazyLock;

use tc_algo::{
    Agreement, AgreementInit, AgreementPeer, Algo, AnyAgreement, AnyAgreementParams, EcCurve,
    ErrorKind,
};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

// A party with a static and an ephemeral key pair on the curve: its own params and what the other
// party takes as its peer
fn party(curve: EcCurve) -> (AnyAgreementParams, AgreementPeer) {
    let mut generator = ALGO.key_pair_generator().get_by_name("EC").unwrap();
    generator.init(curve).unwrap();
    let (key, ephemeral) = (generator.generate().unwrap(), generator.generate().unwrap());
    let params = AnyAgreementParams::new(key.private).with_ephemeral(ephemeral.private);
    let peer = AgreementPeer::new(key.public).with_ephemeral(ephemeral.public);
    (params, peer)
}

fn initialized(params: &AnyAgreementParams) -> AnyAgreement {
    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    ecmqv.init(params).unwrap();
    ecmqv
}

#[test]
fn ecmqv_is_found_by_its_name_in_any_case() {
    for name in ["ECMQV", "ecmqv", "EcMqv"] {
        let ecmqv = ALGO.agreement().get_by_name(name).unwrap();
        assert_eq!(ecmqv.entry().name(), "ECMQV", "{name}");
    }
}

// The OIDs of MQV name the schemes with a KDF, which this agreement is not
#[test]
fn it_has_no_oid_and_a_kdf_scheme_does_not_name_it() {
    let entry = ALGO
        .agreement()
        .algorithms()
        .find(|entry| entry.name() == "ECMQV")
        .unwrap();
    assert!(entry.oids().is_empty());
    assert_eq!(entry.to_string(), "ECMQV");
    let error = ALGO.agreement().get_by_name("1.3.132.1.15.1").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
}

// The GEC 2 vectors of Bouncy Castle's ECTest, on curves below 112 bits
#[cfg(feature = "ec-small-curves")]
mod gec2 {
    use super::ALGO;
    use std::sync::OnceLock;

    use tc_algo::{
        AgreementPeer, AnyAgreementParams, AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey,
        AnyPublicKey,
    };
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_key::{EcPrivateKey, EcPublicKey};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn integer(text: &str) -> PaddedBigUint {
        <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(text)).unwrap()
    }

    // This party's params from its static and ephemeral private keys
    fn params(key: &AnyEcPrivateKey, ephemeral: &AnyEcPrivateKey) -> AnyAgreementParams {
        AnyAgreementParams::new(AnyPrivateKey::Ec(key.clone()))
            .with_ephemeral(AnyPrivateKey::Ec(ephemeral.clone()))
    }

    // The other party's static and ephemeral public keys
    fn peer(key: &AnyEcPublicKey, ephemeral: &AnyEcPublicKey) -> AgreementPeer {
        AgreementPeer::new(AnyPublicKey::Ec(key.clone()))
            .with_ephemeral(AnyPublicKey::Ec(ephemeral.clone()))
    }

    // Bouncy Castle's calculateAgreement: U's static and ephemeral keys, then V's, each a public
    // and a private key; both parties reach the same secret, which this returns
    fn known_answer(keys: [(AnyEcPublicKey, AnyEcPrivateKey); 4]) -> Vec<u8> {
        let [u1, u2, v1, v2] = keys;
        let u = ALGO
            .agreement()
            .calculate("ECMQV", &params(&u1.1, &u2.1), &peer(&v1.0, &v2.0));
        let v = ALGO
            .agreement()
            .calculate("ECMQV", &params(&v1.1, &v2.1), &peer(&u1.0, &u2.0));
        let (u, v) = (u.unwrap(), v.unwrap());
        assert_eq!(u.as_bytes(), v.as_bytes());
        u.as_bytes().to_vec()
    }

    #[test]
    fn the_gec2_vector_on_secp160r1_matches_bouncy_castle() {
        use tc_fp_custom::{SecP160R1FieldElement, SecPCtCurve};

        static CURVE: OnceLock<SecPCtCurve<SecP160R1FieldElement>> = OnceLock::new();
        let named = tc_fp_custom::named_curves::SECP160R1;
        let curve = CURVE.get_or_init(|| named.ct_curve());
        let g = named.ct_generator(curve);
        let keys = [
            (
                "0251B4496FECC406ED0E75A24A3C03206251419DC0",
                "AA374FFC3CE144E6B073307972CB6D57B2A4E982",
            ),
            (
                "03D99CE4D8BF52FA20BD21A962C6556B0F71F4CA1F",
                "149EC7EA3A220A887619B3F9E5B4CA51C7D1779C",
            ),
            (
                "0349B41E0E9C0369C2328739D90F63D56707C6E5BC",
                "45FB58A92A17AD4B15101C66E74F277E2B460866",
            ),
            (
                "02706E5D6E1F640C6E9C804E75DBC14521B1E5F3B5",
                "18C13FCED9EADF884F7C595C8CB565DEFD0CB41E",
            ),
        ]
        .map(|(q, d)| {
            let q = curve.decode_point(&hex(q)).unwrap();
            let public = EcPublicKey::new(g.clone(), &q).unwrap();
            let private = EcPrivateKey::new(g.clone(), integer(d)).unwrap();
            (
                AnyEcPublicKey::Secp160r1(Box::new(public)),
                AnyEcPrivateKey::Secp160r1(Box::new(private)),
            )
        });
        assert_eq!(
            known_answer(keys),
            hex("5A6955CEFDB4E43255FB7FCF718611E4DF8E05AC")
        );
    }

    // sect163k1 has a cofactor of 2
    #[cfg(feature = "ec-f2m")]
    #[test]
    fn the_gec2_vector_on_sect163k1_with_cofactor_two_matches_bouncy_castle() {
        use tc_f2m_custom::{SecT163FieldElement, SecTCtCurve};

        static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
        let named = tc_f2m_custom::named_curves::SECT163K1;
        let curve = CURVE.get_or_init(|| named.ct_curve());
        let g = named.ct_generator(curve);
        let keys = [
            (
                "03037D529FA37E42195F10111127FFB2BB38644806BC",
                "03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D",
            ),
            (
                "02015198E74BC2F1E5C9A62B80248DF0D62B9ADF8429",
                "032FC4C61A8211E6A7C4B8B0C03CF35F7CF20DBD52",
            ),
            (
                "03072783FAAB9549002B4F13140B88132D1C75B3886C",
                "57E8A78E842BF4ACD5C315AA0569DB1703541D96",
            ),
            (
                "03067E3AEA3510D69E8EDD19CB2A703DDC6CF5E56E32",
                "02BD198B83A667A8D908EA1E6F90FD5C6D695DE94F",
            ),
        ]
        .map(|(q, d)| {
            let q = curve.decode_point(&hex(q)).unwrap();
            let public = EcPublicKey::new(g.clone(), &q).unwrap();
            let private = EcPrivateKey::new(g.clone(), integer(d)).unwrap();
            (
                AnyEcPublicKey::Sect163k1(Box::new(public)),
                AnyEcPrivateKey::Sect163k1(Box::new(private)),
            )
        });
        assert_eq!(
            known_answer(keys),
            hex("038359FFD30C0D5FC1E6154F483B73D43E5CF2B503")
        );
    }
}

#[test]
fn both_parties_reach_the_same_secret_as_long_as_a_coordinate() {
    for (curve, size) in [(EcCurve::Secp256r1, 32), (EcCurve::Secp384r1, 48)] {
        let (alice, alice_peer) = party(curve);
        let (bob, bob_peer) = party(curve);
        let alice_secret = ALGO
            .agreement()
            .calculate("ECMQV", &alice, &bob_peer)
            .unwrap();
        let bob_secret = ALGO
            .agreement()
            .calculate("ECMQV", &bob, &alice_peer)
            .unwrap();
        assert_eq!(alice_secret.as_bytes().len(), size, "{curve:?}");
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes(), "{curve:?}");
    }
}

#[test]
fn either_party_without_an_ephemeral_key_is_refused() {
    let (alice, _) = party(EcCurve::Secp256r1);
    let (_, bob_peer) = party(EcCurve::Secp256r1);

    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    let error = ecmqv
        .init(&AnyAgreementParams::new(alice.key().clone()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let error = initialized(&alice)
        .calculate(&AgreementPeer::new(bob_peer.key().clone()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn ecmqv_refuses_user_keying_material() {
    let (alice, _) = party(EcCurve::Secp256r1);
    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    let error = ecmqv.init(&alice.with_ukm(vec![1, 2, 3])).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn keys_on_more_than_one_curve_are_refused() {
    let (p256, p256_peer) = party(EcCurve::Secp256r1);
    let (p384, p384_peer) = party(EcCurve::Secp384r1);

    // This party's ephemeral key on another curve than its static key
    let mixed = AnyAgreementParams::new(p256.key().clone())
        .with_ephemeral(p384.ephemeral().unwrap().clone());
    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    let error = ecmqv.init(&mixed).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    // The other party's keys on another curve, both or one of them
    let ecmqv = initialized(&p256);
    let mixed_peer = AgreementPeer::new(p256_peer.key().clone())
        .with_ephemeral(p384_peer.ephemeral().unwrap().clone());
    for peer in [p384_peer, mixed_peer] {
        let error = ecmqv.calculate(&peer).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(feature = "x25519")]
#[test]
fn an_ephemeral_key_that_is_not_ec_is_refused_on_either_side() {
    let x25519 = ALGO.key_pair_generator().generate("X25519").unwrap();
    let (alice, alice_peer) = party(EcCurve::Secp256r1);

    let params = AnyAgreementParams::new(alice.key().clone()).with_ephemeral(x25519.private);
    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    let error = ecmqv.init(&params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);

    let peer = AgreementPeer::new(alice_peer.key().clone()).with_ephemeral(x25519.public);
    let error = initialized(&alice).calculate(&peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
    let (alice, _) = party(EcCurve::Secp256r1);
    let (_, bob_peer) = party(EcCurve::Secp256r1);
    let mut ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    AgreementInit::init(&mut ecmqv, &alice).unwrap();
    assert_eq!(ecmqv.agreement_size(), 32);
    let mut output = [0; 32];
    ecmqv.calculate_agreement(&bob_peer, &mut output).unwrap();
    assert_eq!(
        output.to_vec(),
        ecmqv.calculate(&bob_peer).unwrap().as_bytes()
    );
    let error = ecmqv
        .calculate_agreement(&bob_peer, &mut [0; 31])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[test]
fn calculating_before_init_is_not_initialized() {
    let (_, bob_peer) = party(EcCurve::Secp256r1);
    let ecmqv = ALGO.agreement().get_by_name("ECMQV").unwrap();
    let error = ecmqv.calculate(&bob_peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn a_failed_init_leaves_no_earlier_key_behind() {
    let (alice, _) = party(EcCurve::Secp256r1);
    let (_, bob_peer) = party(EcCurve::Secp256r1);
    let mut ecmqv = initialized(&alice);
    ecmqv
        .init(&AnyAgreementParams::new(alice.key().clone()))
        .unwrap_err();
    let error = ecmqv.calculate(&bob_peer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn debug_shows_the_name_and_never_the_keys_or_the_secret() {
    let (alice, _) = party(EcCurve::Secp256r1);
    let (_, bob_peer) = party(EcCurve::Secp256r1);
    let ecmqv = initialized(&alice);
    assert_eq!(format!("{ecmqv:?}"), "AnyAgreement { name: \"ECMQV\", .. }");
    let secret = ecmqv.calculate(&bob_peer).unwrap();
    assert_eq!(format!("{secret:?}"), "SharedSecret { len: 32, .. }");
}

#[test]
fn an_agreement_can_move_to_another_thread() {
    fn send<T: Send>(_: T) {}
    let (alice, _) = party(EcCurve::Secp256r1);
    send(initialized(&alice));
}
