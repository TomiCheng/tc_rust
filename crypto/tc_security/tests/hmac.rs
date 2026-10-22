//! HMAC：每個 digest 一列，跟用 digest 工廠自己組出的 HMAC 一致，並對照公開的已知答案。

use tc_digest::TryDigest;
use tc_security::params::AnyParams;
use tc_security::{digest, mac};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 2104：H((K ^ opad) || H((K ^ ipad) || m))，block 用 digest 回報的長度
#[allow(dead_code, reason = "所有 digest 的 feature 都關掉時沒用到")]
fn reference_hmac(digest_name: &str, key: &[u8], message: &[u8]) -> Vec<u8> {
    let block = digest::get_by_name(digest_name).unwrap().byte_length();
    let mut key = if key.len() > block {
        digest::calculate_by_name(digest_name, key).unwrap()
    } else {
        key.to_vec()
    };
    key.resize(block, 0);
    let pad = |byte: u8| key.iter().map(|k| k ^ byte).collect::<Vec<u8>>();
    let inner =
        digest::calculate_by_name(digest_name, &[pad(0x36), message.to_vec()].concat()).unwrap();
    digest::calculate_by_name(digest_name, &[pad(0x5c), inner].concat()).unwrap()
}

// 金鑰比區塊短、剛好、比區塊長三種
#[test]
fn every_hmac_matches_one_built_from_its_digest() {
    for entry in mac::algorithms() {
        let Some(digest_name) = entry.name().strip_prefix("HMAC-") else {
            continue;
        };
        let block = digest::get_by_name(digest_name).unwrap().byte_length();
        for key_len in [20, block, block + 31] {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let message = b"attack at dawn";
            assert_eq!(
                mac::calculate(&mut entry.mac(), &AnyParams::new(key.clone()), message).unwrap(),
                reference_hmac(digest_name, &key, message),
                "{} with a {key_len}-byte key",
                entry.name()
            );
        }
    }
}

// RFC 2202 與 RFC 4231 的測試案例 1，以及由 Python hmac（OpenSSL）算出的 SHA-3 與 SHA-512/256
#[test]
fn hmac_matches_the_published_test_case_1() {
    let vectors: &[(&str, usize, &str)] = &[
        #[cfg(feature = "md5")]
        ("HMAC-MD5", 16, "9294727a3638bb1c13f48ef8158bfc9d"),
        #[cfg(feature = "sha1")]
        ("HMAC-SHA1", 20, "b617318655057264e28bc0b6fb378c8ef146be00"),
        #[cfg(feature = "sha256")]
        (
            "HMAC-SHA256",
            20,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        #[cfg(feature = "sha512-256")]
        (
            "HMAC-SHA512-256",
            20,
            "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab",
        ),
        #[cfg(feature = "sha3-256")]
        (
            "HMAC-SHA3-256",
            20,
            "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
        ),
        #[cfg(feature = "sha3-512")]
        (
            "HMAC-SHA3-512",
            20,
            "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba\
             47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e",
        ),
    ];
    for &(name, key_len, expected) in vectors {
        let entry = mac::get_by_name(name).unwrap();
        let params = AnyParams::new(vec![0x0b; key_len]);
        assert_eq!(
            mac::calculate(&mut entry.mac(), &params, b"Hi There").unwrap(),
            unhex(expected),
            "{name}"
        );
    }
}

#[cfg(all(feature = "sha1", feature = "sha3-256", feature = "keccak-256"))]
#[test]
fn hmac_names_aliases_and_oids_follow_bc() {
    for (name, expected) in [
        ("hmac-sha3-256", "HMAC-SHA3-256"),
        ("HMAC/SHA3-256", "HMAC-SHA3-256"),
        ("HMACSHA3-256", "HMAC-SHA3-256"),
        ("2.16.840.1.101.3.4.2.14", "HMAC-SHA3-256"),
        ("HMACKECCAK256", "HMAC-KECCAK256"),
        ("1.2.840.113549.2.7", "HMAC-SHA1"),
        ("1.3.6.1.5.5.8.1.2", "HMAC-SHA1"),
    ] {
        assert_eq!(
            mac::get_by_name(name).map(|entry| entry.name()),
            Ok(expected),
            "{name}"
        );
    }
}
