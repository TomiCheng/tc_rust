#![cfg(all(
    feature = "cmac",
    feature = "cbc-mac",
    feature = "cfb-mac",
    feature = "iso9797-mac",
    feature = "gost28147-mac",
    feature = "vmpc-mac",
    feature = "siphash",
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "skipjack",
    feature = "idea",
    feature = "rc2",
    feature = "rc5",
))]

// Every MAC of Bouncy Castle's MacUtilities but HMAC against tags Bouncy Castle itself gave, so that
// this table builds what its table builds: the tag length, the padding and the IV left out included
#[path = "vectors/bc_macs.rs"]
mod bc_macs;

use std::sync::LazyLock;

use bc_macs::{ALIASES, VECTORS};
use tc_algo_old::{Algo, AnyMacParams, SecretKey};
use tc_asn1::Asn1Oid;

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn params(key: &str, iv: &str) -> AnyMacParams {
    let params = AnyMacParams::new(SecretKey::new(unhex(key)));
    if iv.is_empty() {
        params
    } else {
        params.with_iv(unhex(iv))
    }
}

#[test]
fn every_tag_is_the_one_bouncy_castle_gave() {
    assert!(VECTORS.len() > 400);
    for &(name, key, iv, message, tag) in VECTORS {
        let expected = unhex(tag);
        let params = params(key, iv);
        let message = unhex(message);

        let mut mac = ALGO
            .mac()
            .get_by_name(name)
            .unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(mac.mac_size(), expected.len(), "{name}");
        mac.init(&params).unwrap_or_else(|_| panic!("{name} {key}"));
        for piece in message.chunks(3) {
            mac.update(piece).unwrap();
        }
        assert_eq!(
            mac.finalize().unwrap(),
            expected,
            "{name} key {key} iv {iv} message of {} bytes",
            message.len()
        );

        // The next message under the same key starts afresh
        mac.update(&message).unwrap();
        assert!(mac.verify(&expected).unwrap(), "{name} again");
    }
}

#[test]
fn every_mechanism_of_bouncy_castle_has_a_vector() {
    for name in [
        "AESCMAC",
        "DESEDECMAC",
        "DESMAC",
        "DESMAC/CFB8",
        "DESMAC64",
        "DESEDEMAC",
        "DESEDEMAC/CFB8",
        "DESEDEMAC64",
        "DESEDEMAC64WITHISO7816-4PADDING",
        "ISO9797ALG3MAC",
        "ISO9797ALG3WITHISO7816-4PADDING",
        "SKIPJACKMAC",
        "SKIPJACKMAC/CFB8",
        "IDEAMAC",
        "IDEAMAC/CFB8",
        "RC2MAC",
        "RC2MAC/CFB8",
        "RC5MAC",
        "RC5MAC/CFB8",
        "GOST28147MAC",
        "VMPCMAC",
        "SIPHASH-2-4",
    ] {
        assert!(
            VECTORS.iter().any(|vector| vector.0 == name),
            "no vector for {name}"
        );
    }
}

#[test]
fn every_alias_of_bouncy_castle_finds_its_mechanism() {
    for &(alias, mechanism) in ALIASES {
        assert_eq!(
            ALGO.mac().get_by_name(alias).unwrap().entry().name(),
            ALGO.mac().get_by_name(mechanism).unwrap().entry().name(),
            "{alias}"
        );
    }
}

#[test]
fn desede_mac_goes_by_the_oid_of_desede_in_cbc_mode() {
    let oid: Asn1Oid = "1.2.840.113549.3.7".parse().unwrap();
    assert_eq!(
        ALGO.mac().get_by_oid(&oid).unwrap().entry().name(),
        "DESEDEMAC"
    );
}

#[test]
fn names_match_without_regard_to_case() {
    assert_eq!(
        ALGO.mac()
            .get_by_name("desmac/cfb8")
            .unwrap()
            .entry()
            .name(),
        "DESMAC/CFB8"
    );
    assert_eq!(
        ALGO.mac().get_by_name("SipHash").unwrap().entry().name(),
        "SIPHASH-2-4"
    );
}

#[test]
fn an_iv_left_out_is_a_zero_block_for_every_mac_that_may_take_one() {
    for (name, key_len) in [
        ("DESMAC", 8),
        ("DESMAC/CFB8", 8),
        ("DESEDEMAC", 24),
        ("DESEDEMAC64WITHISO7816-4PADDING", 24),
        ("SKIPJACKMAC", 10),
        ("IDEAMAC", 16),
        ("RC2MAC", 16),
        ("RC5MAC", 16),
        ("ISO9797ALG3MAC", 16),
        ("GOST28147MAC", 32),
    ] {
        let key = SecretKey::new(vec![0x42; key_len]);
        let without = AnyMacParams::new(key.clone());
        let with_zeros = AnyMacParams::new(key).with_iv(vec![0; 8]);
        assert_eq!(
            ALGO.mac()
                .calculate(name, &without, b"a message of some length")
                .unwrap(),
            ALGO.mac()
                .calculate(name, &with_zeros, b"a message of some length")
                .unwrap(),
            "{name}"
        );
    }
}
