// DH in the agreement table, found by its names as in Bouncy Castle and by nothing else, and the
// agreement it gives: the shared secret, and what init and calculate refuse
use tc_algo::ErrorKind;
use tc_algo::agreement;
use tc_asn1::Asn1Oid;

#[cfg(feature = "dh")]
#[test]
fn dh_is_found_by_its_name_and_its_bouncy_castle_alias_in_any_case() {
    for name in ["DH", "dh", "DIFFIEHELLMAN", "DiffieHellman"] {
        let agreement = agreement::get_by_name(name).unwrap();
        assert_eq!(agreement.entry().name(), "DH", "{name}");
        assert_eq!(agreement.to_string(), "DH", "{name}");
    }
}

#[cfg(feature = "dh")]
#[test]
fn the_table_has_dh_once_and_without_an_oid() {
    let entries: Vec<_> = agreement::algorithms()
        .filter(|entry| entry.name() == "DH")
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].oids().is_empty());
    assert_eq!(entries[0].to_string(), "DH");
}

#[test]
fn a_name_not_in_the_table_is_an_unknown_agreement() {
    for name in [
        "",
        "D-H",
        "DIFFIE-HELLMAN",
        "DH/NONE",
        "1.2.840.113549.1.3.1",
    ] {
        let error = agreement::get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownAgreement, "{name:?}");
    }
}

// PKCS #3's dhKeyAgreement names the key, not an agreement, and Bouncy Castle maps it to none
#[test]
fn the_oid_of_a_dh_key_is_an_unknown_agreement() {
    let oid: Asn1Oid = "1.2.840.113549.1.3.1".parse().unwrap();
    let error = agreement::get_by_oid(&oid).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
}

#[cfg(feature = "dh")]
mod with_dh {
    use tc_algo::ErrorKind;
    use tc_algo::agreement::{
        self, Agreement, AgreementInit, AgreementPeer, AnyAgreement, AnyAgreementParams,
    };
    use tc_algo::generate;
    use tc_algo::params::{AnyPrivateKey, AnyPublicKey};
    use tc_bigint::PaddedBigUint;
    use tc_dh_key::standard_groups::{rfc2409_1024, rfc3526_2048};
    use tc_dh_key::{DhParameters, DhPrivateKey, DhPublicKey};

    fn key_pair(group: DhParameters) -> (AnyPublicKey, AnyPrivateKey) {
        let mut generator = generate::key_pair::get_by_name("DH").unwrap();
        generator.init(group).unwrap();
        let pair = generator.generate().unwrap();
        (pair.public, pair.private)
    }

    // p = 23 and g = 5: 5^4 = 4 and 5^3 = 10 mod 23, and 10^4 = 4^3 = 18 mod 23
    fn toy() -> DhParameters {
        DhParameters::new(PaddedBigUint::from(23u8), PaddedBigUint::from(5u8)).with_m(0)
    }

    fn toy_private(x: u8) -> AnyAgreementParams {
        let key = DhPrivateKey::new(PaddedBigUint::from(x), toy());
        AnyAgreementParams::new(AnyPrivateKey::Dh(key))
    }

    fn toy_public(y: u8) -> AgreementPeer {
        let key = DhPublicKey::new(PaddedBigUint::from(y), toy());
        AgreementPeer::new(AnyPublicKey::Dh(key))
    }

    fn initialized(params: &AnyAgreementParams) -> AnyAgreement {
        let mut dh = agreement::get_by_name("DH").unwrap();
        dh.init(params).unwrap();
        dh
    }

    #[test]
    fn both_parties_reach_the_same_secret_as_long_as_p() {
        let (alice_public, alice_private) = key_pair(rfc3526_2048());
        let (bob_public, bob_private) = key_pair(rfc3526_2048());
        let alice = initialized(&alice_private.into());
        let alice_secret = alice.calculate(&bob_public.into()).unwrap();
        let bob_secret =
            agreement::calculate("DH", &bob_private.into(), &alice_public.into()).unwrap();
        assert_eq!(alice_secret.as_bytes().len(), 256);
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn the_secret_in_a_toy_group_is_y_to_the_x_mod_p() {
        let alice = agreement::calculate("DH", &toy_private(4), &toy_public(10)).unwrap();
        let bob = agreement::calculate("DH", &toy_private(3), &toy_public(4)).unwrap();
        assert_eq!(alice.as_bytes(), [18]);
        assert_eq!(bob.as_bytes(), [18]);
    }

    #[test]
    fn the_trait_writes_the_secret_into_a_buffer_of_agreement_size() {
        let mut dh = agreement::get_by_name("DH").unwrap();
        AgreementInit::init(&mut dh, &toy_private(4)).unwrap();
        assert_eq!(dh.agreement_size(), 1);
        let mut output = [0; 1];
        dh.calculate_agreement(&toy_public(10), &mut output)
            .unwrap();
        assert_eq!(output, [18]);
        let error = dh
            .calculate_agreement(&toy_public(10), &mut [])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn dh_refuses_user_keying_material() {
        let mut dh = agreement::get_by_name("DH").unwrap();
        let error = dh
            .init(&toy_private(4).with_ukm(vec![1, 2, 3]))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn dh_refuses_an_ephemeral_key_of_the_other_party() {
        let dh = initialized(&toy_private(4));
        let ephemeral = DhPublicKey::new(PaddedBigUint::from(4u8), toy());
        let peer = toy_public(10).with_ephemeral(AnyPublicKey::Dh(ephemeral));
        let error = dh.calculate(&peer).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn a_private_key_alone_makes_params_without_user_keying_material() {
        let key = DhPrivateKey::new(PaddedBigUint::from(4u8), toy());
        let params = AnyAgreementParams::from(AnyPrivateKey::Dh(key));
        assert!(matches!(params.key(), AnyPrivateKey::Dh(_)));
        assert!(params.ukm().is_none());
    }

    #[test]
    fn a_public_key_alone_makes_a_peer_without_an_ephemeral_key() {
        let key = DhPublicKey::new(PaddedBigUint::from(10u8), toy());
        let peer = AgreementPeer::from(AnyPublicKey::Dh(key));
        assert!(matches!(peer.key(), AnyPublicKey::Dh(_)));
        assert!(peer.ephemeral().is_none());
    }

    #[test]
    fn a_public_key_of_another_group_or_a_weak_one_is_refused() {
        let (_, private) = key_pair(rfc3526_2048());
        let (other_group, _) = key_pair(rfc2409_1024());
        let one = DhPublicKey::new(PaddedBigUint::from(1u8), rfc3526_2048());
        let dh = initialized(&AnyAgreementParams::new(private));
        for public_key in [other_group, AnyPublicKey::Dh(one)] {
            let error = dh.calculate(&public_key.into()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
        }
    }

    // 2 has order 11 modulo 23, so 2^11 = 1
    #[test]
    fn a_shared_secret_of_one_is_refused() {
        let error = agreement::calculate("DH", &toy_private(11), &toy_public(2)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn calculating_before_init_is_not_initialized() {
        let dh = agreement::get_by_name("DH").unwrap();
        let error = dh.calculate(&toy_public(10)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = dh
            .calculate_agreement(&toy_public(10), &mut [0])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn a_failed_init_leaves_no_earlier_key_behind() {
        let mut dh = initialized(&toy_private(4));
        dh.init(&toy_private(4).with_ukm(vec![1])).unwrap_err();
        let error = dh.calculate(&toy_public(10)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn debug_shows_the_name_and_never_the_key_or_the_secret() {
        let dh = initialized(&toy_private(4));
        assert_eq!(format!("{dh:?}"), "AnyAgreement { name: \"DH\", .. }");
        let secret = dh.calculate(&toy_public(10)).unwrap();
        assert_eq!(format!("{secret:?}"), "SharedSecret { len: 1, .. }");
    }

    #[test]
    fn an_agreement_can_move_to_another_thread() {
        fn send<T: Send>(_: T) {}
        send(initialized(&toy_private(4)));
    }
}
