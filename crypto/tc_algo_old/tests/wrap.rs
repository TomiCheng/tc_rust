#![cfg(all(
    feature = "rfc3394-wrap",
    feature = "rfc5649-wrap",
    feature = "rfc3211-wrap",
    feature = "aes",
    feature = "aria",
    feature = "camellia",
    feature = "seed",
    feature = "des",
    feature = "desede",
))]

// Every wrapper against what Bouncy Castle's WrapperUtilities gave, and what each refuses
#[path = "vectors/bc_wraps.rs"]
mod bc_wraps;

use bc_wraps::VECTORS;
use tc_algo_old::{Algo, AnyWrapParams, ErrorKind, Policy, SecretKey, WrapDirection};
use tc_asn1::Asn1Oid;

const NAMES: [&str; 11] = [
    "AESWRAP",
    "ARIAWRAP",
    "CAMELLIAWRAP",
    "SEEDWRAP",
    "AESWRAPPAD",
    "ARIAWRAPPAD",
    "AESRFC3211WRAP",
    "ARIARFC3211WRAP",
    "CAMELLIARFC3211WRAP",
    "DESRFC3211WRAP",
    "DESEDERFC3211WRAP",
];

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn params(kek: Vec<u8>, iv: Vec<u8>) -> AnyWrapParams {
    let params = AnyWrapParams::new(SecretKey::new(kek));
    if iv.is_empty() {
        params
    } else {
        params.with_iv(iv)
    }
}

fn aes_params() -> AnyWrapParams {
    AnyWrapParams::new(SecretKey::new(vec![0x42; 16]))
}

#[test]
fn every_wrapped_key_of_bouncy_castle_unwraps_and_the_deterministic_ones_match() {
    assert!(VECTORS.len() > 200);
    let algo = Algo::new();
    for &(name, kek, iv, key, wrapped) in VECTORS {
        let params = params(unhex(kek), unhex(iv));
        let (key, wrapped) = (unhex(key), unhex(wrapped));
        let mut wrapper = algo.wrap().get_by_name(name).unwrap();

        wrapper.init(WrapDirection::Unwrap, &params).unwrap();
        assert_eq!(
            wrapper.unwrap_key(&wrapped).unwrap().key,
            key,
            "{name} kek {kek} iv {iv}"
        );

        wrapper.init(WrapDirection::Wrap, &params).unwrap();
        let ours = wrapper.wrap_key(&key).unwrap();
        if !name.contains("RFC3211") {
            assert_eq!(ours, wrapped, "{name} kek {kek} iv {iv}");
        }
    }
}

#[test]
fn every_row_has_a_vector_and_nothing_else_is_listed() {
    let algo = Algo::new();
    let listed: Vec<&str> = algo.wrap().algorithms().map(|entry| entry.name()).collect();
    assert_eq!(listed, NAMES);
    for name in NAMES {
        assert!(VECTORS.iter().any(|vector| vector.0 == name), "{name}");
    }
}

#[test]
fn the_aliases_of_bouncy_castle_find_their_rows() {
    let algo = Algo::new();
    for (alias, row) in [
        ("AESKW", "AESWRAP"),
        ("aeskwp", "AESWRAPPAD"),
        ("AESRFC5649WRAP", "AESWRAPPAD"),
        ("ARIAKW", "ARIAWRAP"),
        ("ARIAKWP", "ARIAWRAPPAD"),
        ("SEEDKW", "SEEDWRAP"),
        ("2.16.840.1.101.3.4.1.45", "AESWRAP"),
    ] {
        assert_eq!(algo.wrap().get_by_name(alias).unwrap().entry().name(), row);
    }
}

#[test]
fn the_oids_of_bouncy_castle_find_their_rows() {
    let algo = Algo::new();
    for (oid, row) in [
        ("2.16.840.1.101.3.4.1.5", "AESWRAP"),
        ("2.16.840.1.101.3.4.1.25", "AESWRAP"),
        ("2.16.840.1.101.3.4.1.45", "AESWRAP"),
        ("2.16.840.1.101.3.4.1.8", "AESWRAPPAD"),
        ("2.16.840.1.101.3.4.1.28", "AESWRAPPAD"),
        ("2.16.840.1.101.3.4.1.48", "AESWRAPPAD"),
        ("1.2.410.200046.1.1.40", "ARIAWRAP"),
        ("1.2.410.200046.1.1.41", "ARIAWRAP"),
        ("1.2.410.200046.1.1.42", "ARIAWRAP"),
        ("1.2.410.200046.1.1.43", "ARIAWRAPPAD"),
        ("1.2.410.200046.1.1.44", "ARIAWRAPPAD"),
        ("1.2.410.200046.1.1.45", "ARIAWRAPPAD"),
        ("1.2.392.200011.61.1.1.3.2", "CAMELLIAWRAP"),
        ("1.2.392.200011.61.1.1.3.3", "CAMELLIAWRAP"),
        ("1.2.392.200011.61.1.1.3.4", "CAMELLIAWRAP"),
        ("1.2.410.200004.7.1.1.1", "SEEDWRAP"),
    ] {
        let parsed: Asn1Oid = oid.parse().unwrap();
        assert_eq!(
            algo.wrap().get_by_oid(&parsed).unwrap().entry().name(),
            row,
            "{oid}"
        );
    }
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_an_unknown_wrapper() {
    let algo = Algo::new();
    let oid: Asn1Oid = "1.2.3.4".parse().unwrap();
    assert_eq!(
        algo.wrap().get_by_name("NO-SUCH").unwrap_err().kind(),
        ErrorKind::UnknownWrapper
    );
    assert_eq!(
        algo.wrap().get_by_oid(&oid).unwrap_err().kind(),
        ErrorKind::UnknownWrapper
    );
}

#[test]
fn rfc3211_output_differs_each_time_and_each_one_unwraps() {
    let algo = Algo::new();
    let params = params(vec![0x42; 16], vec![0x24; 16]);
    let key = [0x11; 16];
    let first = algo
        .wrap()
        .wrap_key("AESRFC3211WRAP", &params, &key)
        .unwrap();
    let second = algo
        .wrap()
        .wrap_key("AESRFC3211WRAP", &params, &key)
        .unwrap();
    assert_ne!(first, second);
    for wrapped in [first, second] {
        assert_eq!(
            algo.wrap()
                .unwrap_key("AESRFC3211WRAP", &params, &wrapped)
                .unwrap()
                .key,
            key
        );
    }
}

#[test]
fn rfc3211_refuses_a_missing_iv_or_one_that_is_not_a_block() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESRFC3211WRAP").unwrap();
    assert_eq!(
        wrapper
            .init(WrapDirection::Wrap, &aes_params())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        wrapper
            .init(WrapDirection::Wrap, &aes_params().with_iv(vec![0; 8]))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn an_iv_of_the_wrong_length_is_refused() {
    let algo = Algo::new();
    for (name, iv_len) in [("AESWRAP", 4), ("AESWRAPPAD", 8)] {
        let mut wrapper = algo.wrap().get_by_name(name).unwrap();
        assert_eq!(
            wrapper
                .init(WrapDirection::Wrap, &aes_params().with_iv(vec![0; iv_len]))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidParams,
            "{name}"
        );
    }
}

#[test]
fn a_kek_of_a_length_the_cipher_does_not_take_is_refused() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESWRAP").unwrap();
    let params = AnyWrapParams::new(SecretKey::new(vec![0; 15]));
    assert_eq!(
        wrapper
            .init(WrapDirection::Wrap, &params)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn a_changed_wrapped_key_is_refused_as_an_invalid_ciphertext() {
    let algo = Algo::new();
    for name in ["AESWRAP", "AESWRAPPAD"] {
        let mut wrapped = algo
            .wrap()
            .wrap_key(name, &aes_params(), &[0x11; 16])
            .unwrap();
        wrapped[3] ^= 1;
        assert_eq!(
            algo.wrap()
                .unwrap_key(name, &aes_params(), &wrapped)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidCiphertext,
            "{name}"
        );
    }
}

#[test]
fn a_wrapped_key_of_the_wrong_length_is_refused_as_an_invalid_ciphertext() {
    let algo = Algo::new();
    assert_eq!(
        algo.wrap()
            .unwrap_key("AESWRAP", &aes_params(), &[0; 25])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidCiphertext
    );
}

#[test]
fn a_key_rfc3394_cannot_wrap_is_refused_as_the_wrong_length() {
    let algo = Algo::new();
    assert_eq!(
        algo.wrap()
            .wrap_key("AESWRAP", &aes_params(), &[0; 15])
            .unwrap_err()
            .kind(),
        ErrorKind::DataLength
    );
}

#[test]
fn a_wrapper_works_only_in_the_direction_it_was_initialized_for() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESWRAP").unwrap();
    wrapper.init(WrapDirection::Wrap, &aes_params()).unwrap();
    assert_eq!(
        wrapper.unwrap_key(&[0; 24]).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    wrapper.init(WrapDirection::Unwrap, &aes_params()).unwrap();
    assert_eq!(
        wrapper.wrap_key(&[0; 16]).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn a_wrapper_refuses_to_run_before_a_successful_init() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESWRAP").unwrap();
    assert_eq!(
        wrapper.wrap_key(&[0; 16]).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        wrapper.unwrap_key(&[0; 24]).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESWRAP").unwrap();
    wrapper.init(WrapDirection::Wrap, &aes_params()).unwrap();
    assert!(
        wrapper
            .init(WrapDirection::Wrap, &aes_params().with_iv(vec![0; 3]))
            .is_err()
    );
    assert_eq!(
        wrapper.wrap_key(&[0; 16]).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );

    let mut required = algo.wrap().get_by_name("AESRFC3211WRAP").unwrap();
    required
        .init(WrapDirection::Wrap, &aes_params().with_iv(vec![0; 16]))
        .unwrap();
    assert!(required.init(WrapDirection::Wrap, &aes_params()).is_err());
    assert_eq!(
        required.wrap_key(&[0; 16]).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn a_denied_wrapper_is_not_listed_but_can_still_be_got() {
    let mut algo = Algo::new();
    algo.set_policy(Policy::new().with_deny(["AESKW"]));
    let listed: Vec<&str> = algo.wrap().algorithms().map(|entry| entry.name()).collect();
    assert!(!listed.contains(&"AESWRAP"));
    assert!(listed.contains(&"AESWRAPPAD"));
    assert!(algo.wrap().get_by_name("AESWRAP").is_ok());
}

#[test]
fn debug_and_display_show_the_name_and_never_the_key() {
    let algo = Algo::new();
    let mut wrapper = algo.wrap().get_by_name("AESWRAP").unwrap();
    wrapper.init(WrapDirection::Wrap, &aes_params()).unwrap();
    assert_eq!(wrapper.to_string(), "AESWRAP");
    assert_eq!(
        format!("{wrapper:?}"),
        "AnyWrapper { name: \"AESWRAP\", .. }"
    );
    assert_eq!(
        wrapper.entry().to_string(),
        "AESWRAP  [id-aes128-wrap, id-aes192-wrap, id-aes256-wrap]"
    );
    let unwrapped = format!("{:?}", aes_params());
    assert!(!unwrapped.contains("66"), "{unwrapped}");
}
