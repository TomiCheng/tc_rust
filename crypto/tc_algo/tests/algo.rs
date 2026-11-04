use tc_algo::{Algo, Policy};

#[test]
fn a_new_instance_starts_with_an_empty_policy() {
    let algo = Algo::new();
    assert!(algo.policy().allow().is_empty());
    assert!(algo.policy().deny().is_empty());
}

#[test]
fn setting_a_policy_again_replaces_the_whole_of_the_one_before() {
    let mut algo = Algo::new();
    algo.set_policy(Policy::new().with_allow(["SHA-256"]).with_deny(["MD5"]));
    algo.set_policy(Policy::new().with_deny(["SHA-1"]));

    assert!(algo.policy().allow().is_empty());
    assert_eq!(algo.policy().deny().len(), 1);
    assert!(algo.policy().deny().contains("SHA-1"));
}

#[cfg(all(feature = "sha1", feature = "sha256"))]
mod digests {
    use tc_algo::{Algo, Policy};
    use tc_asn1::Asn1Oid;

    const SHA1_OID: &str = "1.3.14.3.2.26";

    fn listed(algo: &Algo) -> Vec<&'static str> {
        algo.digest()
            .algorithms()
            .map(|entry| entry.name())
            .collect()
    }

    fn with(policy: Policy) -> Algo {
        let mut algo = Algo::new();
        algo.set_policy(policy);
        algo
    }

    #[test]
    fn without_a_policy_every_digest_enabled_is_listed() {
        let names = listed(&Algo::new());
        assert!(names.contains(&"SHA-1"));
        assert!(names.contains(&"SHA-256"));
    }

    #[test]
    fn a_denied_digest_is_not_listed_but_can_still_be_got_by_name_and_by_oid() {
        let algo = with(Policy::new().with_deny(["SHA-1"]));
        assert!(!listed(&algo).contains(&"SHA-1"));
        assert!(listed(&algo).contains(&"SHA-256"));

        let oid: Asn1Oid = SHA1_OID.parse().unwrap();
        assert_eq!(
            algo.digest().get_by_name("SHA-1").unwrap().entry().name(),
            "SHA-1"
        );
        assert_eq!(
            algo.digest().get_by_oid(&oid).unwrap().entry().name(),
            "SHA-1"
        );
    }

    #[test]
    fn an_allow_list_lists_only_its_own_names_but_others_can_still_be_got() {
        let algo = with(Policy::new().with_allow(["SHA-256"]));
        assert_eq!(listed(&algo), ["SHA-256"]);
        assert!(algo.digest().get_by_name("SHA-1").is_ok());
    }

    #[test]
    fn a_name_in_both_lists_is_not_listed() {
        let algo = with(
            Policy::new()
                .with_allow(["SHA-1", "SHA-256"])
                .with_deny(["SHA-1"]),
        );
        assert_eq!(listed(&algo), ["SHA-256"]);
    }

    #[test]
    fn a_rule_finds_its_row_by_an_alias_and_without_regard_to_case() {
        for rule in ["SHA1", "sha1", "sha-1"] {
            let algo = with(Policy::new().with_deny([rule]));
            assert!(!listed(&algo).contains(&"SHA-1"), "{rule}");
        }
    }

    #[test]
    fn an_allow_list_of_names_that_match_nothing_lists_nothing() {
        let algo = with(Policy::new().with_allow(["NO-SUCH-DIGEST"]));
        assert!(listed(&algo).is_empty());
    }

    #[test]
    fn setting_a_policy_after_the_list_was_made_makes_it_again() {
        let mut algo = with(Policy::new().with_deny(["SHA-1"]));
        assert!(!listed(&algo).contains(&"SHA-1"));

        algo.set_policy(Policy::new().with_deny(["SHA-256"]));
        assert!(listed(&algo).contains(&"SHA-1"));
        assert!(!listed(&algo).contains(&"SHA-256"));
    }

    #[test]
    fn asking_for_the_list_twice_gives_the_same_list() {
        let algo = with(Policy::new().with_deny(["SHA-1"]));
        assert_eq!(listed(&algo), listed(&algo));
    }

    #[test]
    fn a_digest_obtained_from_a_denied_row_still_works() {
        let algo = with(Policy::new().with_deny(["SHA-1"]));
        let mut digest = algo.digest().get_by_name("SHA-1").unwrap();
        digest.update(b"abc");
        assert_eq!(digest.finalize().len(), 20);
    }
}

#[cfg(all(feature = "hmac", feature = "sha1", feature = "sha256"))]
mod macs {
    use tc_algo::{Algo, AnyMac, AnyMacParams, ErrorKind, Policy, SecretKey};
    use tc_asn1::Asn1Oid;

    const HMAC_SHA1_OID: &str = "1.2.840.113549.2.7";

    fn listed(algo: &Algo) -> Vec<String> {
        algo.mac()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .collect()
    }

    fn lists(algo: &Algo, name: &str) -> bool {
        listed(algo).iter().any(|listed| listed == name)
    }

    fn with(policy: Policy) -> Algo {
        let mut algo = Algo::new();
        algo.set_policy(policy);
        algo
    }

    fn tag(mut mac: AnyMac) -> Vec<u8> {
        mac.init(&AnyMacParams::new(SecretKey::new(vec![0x42; 16])))
            .unwrap();
        mac.update(b"message").unwrap();
        mac.finalize().unwrap()
    }

    #[test]
    fn without_a_policy_every_mac_enabled_is_listed() {
        let algo = Algo::new();
        assert!(lists(&algo, "HMAC-SHA-1"));
        assert!(lists(&algo, "HMAC-SHA-256"));
    }

    #[test]
    fn a_denied_mac_is_not_listed_but_can_still_be_got_by_name_and_by_oid() {
        let algo = with(Policy::new().with_deny(["HMAC-SHA-1"]));
        assert!(!lists(&algo, "HMAC-SHA-1"));
        assert!(lists(&algo, "HMAC-SHA-256"));

        let oid: Asn1Oid = HMAC_SHA1_OID.parse().unwrap();
        assert_eq!(
            algo.mac().get_by_name("HMAC-SHA-1").unwrap().entry().name(),
            "HMAC-SHA-1"
        );
        assert_eq!(
            algo.mac().get_by_oid(&oid).unwrap().entry().name(),
            "HMAC-SHA-1"
        );
    }

    #[test]
    fn an_allow_list_lists_only_its_own_names_but_others_can_still_be_got() {
        let algo = with(Policy::new().with_allow(["HMAC-SHA-256"]));
        assert_eq!(listed(&algo), ["HMAC-SHA-256"]);
        assert!(algo.mac().get_by_name("HMAC-SHA-1").is_ok());
    }

    #[test]
    fn a_rule_finds_its_row_by_an_alias_and_without_regard_to_case() {
        for rule in ["HMACSHA1", "hmac/sha1", "hmac-sha-1"] {
            let algo = with(Policy::new().with_deny([rule]));
            assert!(!lists(&algo, "HMAC-SHA-1"), "{rule}");
        }
    }

    #[test]
    fn denying_a_digest_leaves_the_hmac_over_it_listed() {
        let algo = with(Policy::new().with_deny(["SHA-1"]));
        assert!(lists(&algo, "HMAC-SHA-1"));
    }

    #[test]
    fn setting_a_policy_after_the_list_was_made_makes_it_again() {
        let mut algo = with(Policy::new().with_deny(["HMAC-SHA-1"]));
        assert!(!lists(&algo, "HMAC-SHA-1"));

        algo.set_policy(Policy::new().with_deny(["HMAC-SHA-256"]));
        assert!(lists(&algo, "HMAC-SHA-1"));
        assert!(!lists(&algo, "HMAC-SHA-256"));
    }

    #[test]
    fn an_unknown_name_or_oid_is_reported_as_an_unknown_mac() {
        let algo = Algo::new();
        let oid: Asn1Oid = "1.2.3.4".parse().unwrap();
        assert_eq!(
            algo.mac().get_by_name("NO-SUCH-MAC").unwrap_err().kind(),
            ErrorKind::UnknownMac
        );
        assert_eq!(
            algo.mac().get_by_oid(&oid).unwrap_err().kind(),
            ErrorKind::UnknownMac
        );
    }

    #[test]
    fn a_mac_keeps_working_after_the_instance_it_came_from_is_gone() {
        let kept = {
            let algo = Algo::new();
            algo.mac().get_by_name("HMAC-SHA-256").unwrap()
        };
        assert_eq!(kept.entry().name(), "HMAC-SHA-256");

        let fresh = Algo::new().mac().get_by_name("HMAC-SHA-256").unwrap();
        assert_eq!(tag(kept), tag(fresh));
    }

    #[test]
    fn a_listed_entry_gives_a_mac_that_works() {
        let algo = Algo::new();
        let entry = algo
            .mac()
            .algorithms()
            .find(|entry| entry.name() == "HMAC-SHA-256")
            .unwrap();
        assert_eq!(tag(entry.mac()).len(), 32);
    }

    #[test]
    fn a_clone_of_an_instance_keeps_its_policy() {
        let algo = with(Policy::new().with_deny(["HMAC-SHA-1"]));
        assert!(!lists(&algo.clone(), "HMAC-SHA-1"));
    }

    #[test]
    fn an_instance_can_be_shared_between_threads() {
        fn shareable<T: Send + Sync>(_: &T) {}
        shareable(&Algo::new());
    }
}
