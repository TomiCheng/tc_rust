#![cfg(all(
    feature = "gmac",
    feature = "aes",
    feature = "poly1305",
    feature = "kmac",
    feature = "dstu7564-mac",
    feature = "dstu7624-mac",
    feature = "skein-mac",
))]

// The MACs that Bouncy Castle has as classes but not in its MacUtilities, against tags its classes
// gave, and what each refuses
#[path = "vectors/bc_mac_classes.rs"]
mod bc_mac_classes;

use bc_mac_classes::VECTORS;
use tc_algo::ErrorKind;
use tc_algo::mac::{self, AnyMacParams};
use tc_algo::params::SecretKey;
use tc_asn1::Asn1Oid;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn params(key_len: usize) -> AnyMacParams {
    AnyMacParams::new(SecretKey::new(vec![0x42; key_len]))
}

#[test]
fn every_tag_is_the_one_bouncy_castle_gave() {
    assert!(VECTORS.len() > 500);
    for &(name, key, iv, message, tag) in VECTORS {
        let expected = unhex(tag);
        let mut params = AnyMacParams::new(SecretKey::new(unhex(key)));
        if !iv.is_empty() {
            params = params.with_iv(unhex(iv));
        }
        let message = unhex(message);

        let mut mac = mac::get_by_name(name).unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(mac.mac_size(), expected.len(), "{name}");
        mac.init(&params).unwrap_or_else(|_| panic!("{name} {key}"));
        mac.update(&message).unwrap();
        assert_eq!(
            mac.finalize().unwrap(),
            expected,
            "{name} key {key} iv {iv} message of {} bytes",
            message.len()
        );
    }
}

#[test]
fn every_row_has_a_vector() {
    for entry in mac::algorithms() {
        let name = entry.name();
        let outside = ["AES-GMAC", "POLY1305", "KMAC", "DSTU", "SKEIN-MAC"]
            .iter()
            .any(|prefix| name.starts_with(prefix));
        if outside {
            assert!(
                VECTORS.iter().any(|vector| vector.0 == name),
                "no vector for {name}"
            );
        }
    }
}

#[test]
fn the_oids_bouncy_castle_defines_find_their_rows() {
    for (oid, row) in [
        ("2.16.840.1.101.3.4.2.19", "KMAC128"),
        ("2.16.840.1.101.3.4.2.21", "KMAC128"),
        ("2.16.840.1.101.3.4.2.20", "KMAC256"),
        ("2.16.840.1.101.3.4.2.22", "KMAC256"),
        ("1.2.804.2.1.1.1.1.2.2.4", "DSTU7564MAC-256"),
        ("1.2.804.2.1.1.1.1.2.2.5", "DSTU7564MAC-384"),
        ("1.2.804.2.1.1.1.1.2.2.6", "DSTU7564MAC-512"),
        ("1.2.804.2.1.1.1.1.3.4.1", "DSTU7624MAC-128"),
        ("1.2.804.2.1.1.1.1.3.4.2", "DSTU7624MAC-256"),
        ("1.2.804.2.1.1.1.1.3.4.3", "DSTU7624MAC-512"),
    ] {
        let parsed: Asn1Oid = oid.parse().unwrap();
        assert_eq!(mac::get_by_oid(&parsed).unwrap().entry().name(), row);
    }
}

#[test]
fn gmac_requires_a_nonce_and_refuses_the_same_key_and_nonce_again() {
    let mut mac = mac::get_by_name("AES-GMAC").unwrap();
    assert_eq!(
        mac.init(&params(16)).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );

    let with_nonce = params(16).with_iv(vec![1; 12]);
    mac.init(&with_nonce).unwrap();
    assert_eq!(
        mac.init(&with_nonce).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    assert!(mac.init(&params(16).with_iv(vec![2; 12])).is_ok());
}

#[test]
fn gmac_and_poly1305_take_a_new_init_after_each_message() {
    let mut gmac = mac::get_by_name("AES-GMAC").unwrap();
    gmac.init(&params(16).with_iv(vec![1; 12])).unwrap();
    gmac.update(b"message").unwrap();
    gmac.finalize().unwrap();
    assert_eq!(
        gmac.update(b"message").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );

    let mut poly = mac::get_by_name("POLY1305").unwrap();
    poly.init(&params(32)).unwrap();
    poly.update(b"message").unwrap();
    poly.finalize().unwrap();
    assert_eq!(
        poly.update(b"message").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        poly.finalize().unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn the_others_start_the_next_message_under_the_same_key() {
    for (name, key_len, message) in [
        ("KMAC128", 16, &b"message"[..]),
        ("KMAC256", 16, &b"message"[..]),
        ("DSTU7564MAC-256", 16, &b"message"[..]),
        ("DSTU7624MAC-128", 16, &[7; 16][..]),
        ("SKEIN-MAC-512-256", 16, &b"message"[..]),
    ] {
        let mut mac = mac::get_by_name(name).unwrap();
        mac.init(&params(key_len)).unwrap();
        mac.update(message).unwrap();
        let first = mac.finalize().unwrap();
        mac.update(message).unwrap();
        assert_eq!(mac.finalize().unwrap(), first, "{name}");
    }
}

#[test]
fn poly1305_and_skein_refuse_a_key_of_the_wrong_length() {
    let mut poly = mac::get_by_name("POLY1305").unwrap();
    assert_eq!(
        poly.init(&params(31)).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    let mut skein = mac::get_by_name("SKEIN-MAC-512-256").unwrap();
    assert_eq!(
        skein.init(&params(15)).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn the_keyed_macs_outside_the_table_refuse_an_iv() {
    for name in [
        "POLY1305",
        "KMAC128",
        "DSTU7564MAC-256",
        "DSTU7624MAC-128",
        "SKEIN-MAC-512-256",
    ] {
        let mut mac = mac::get_by_name(name).unwrap();
        assert_eq!(
            mac.init(&params(32).with_iv(vec![0; 16]))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidParams,
            "{name}"
        );
    }
}

#[test]
fn dstu7624_mac_takes_only_whole_blocks() {
    let mut mac = mac::get_by_name("DSTU7624MAC-128").unwrap();
    mac.init(&params(16)).unwrap();
    mac.update(&[0; 15]).unwrap();
    assert_eq!(mac.finalize().unwrap_err().kind(), ErrorKind::DataLength);
}

#[test]
fn dstu7624_mac_refuses_a_key_its_block_size_does_not_take() {
    let mut mac = mac::get_by_name("DSTU7624MAC-512").unwrap();
    assert_eq!(
        mac.init(&params(32)).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
}

// Bouncy Castle's Dstu7564Mac throws IndexOutOfRangeException here, writing its padding past the end
#[test]
fn dstu7564_mac_takes_a_key_of_a_whole_number_of_blocks() {
    let mut mac = mac::get_by_name("DSTU7564MAC-256").unwrap();
    mac.init(&params(64)).unwrap();
    mac.update(b"message").unwrap();
    assert_eq!(mac.finalize().unwrap().len(), 32);
}

#[test]
fn names_match_without_regard_to_case() {
    assert_eq!(
        mac::get_by_name("aes-gmac").unwrap().entry().name(),
        "AES-GMAC"
    );
    assert_eq!(
        mac::get_by_name("skein-mac-512-256")
            .unwrap()
            .entry()
            .name(),
        "SKEIN-MAC-512-256"
    );
}
