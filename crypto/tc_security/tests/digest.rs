//! digest 工廠：以 "abc" 的公開答案驗證每個演算法，並檢查名稱與 OID 查詢。

use tc_digest::Digest;
use tc_security::SecurityError;
use tc_security::digest::{self, Algorithm};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// RFC 1319、1320、1321、FIPS 180-4 與 FIPS 202 的 "abc" 範例；SHAKE 由 Python hashlib（OpenSSL）算出，
// 原始 Keccak 由先以 hashlib 的 SHA-3 驗證過的 Python 參考實作算出
const ABC: &[(Algorithm, &str)] = &[
    #[cfg(feature = "md2")]
    (Algorithm::Md2, "da853b0d3f88d99b30283a69e6ded6bb"),
    #[cfg(feature = "md4")]
    (Algorithm::Md4, "a448017aaf21d8525fc10ae87aa6729d"),
    #[cfg(feature = "md5")]
    (Algorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
    #[cfg(feature = "sha1")]
    (Algorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    #[cfg(feature = "sha224")]
    (
        Algorithm::Sha224,
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    ),
    #[cfg(feature = "sha256")]
    (
        Algorithm::Sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    #[cfg(feature = "sha384")]
    (
        Algorithm::Sha384,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    ),
    #[cfg(feature = "sha512")]
    (
        Algorithm::Sha512,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    #[cfg(feature = "sha512-224")]
    (
        Algorithm::Sha512_224,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    ),
    #[cfg(feature = "sha512-256")]
    (
        Algorithm::Sha512_256,
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    ),
    #[cfg(feature = "sha3-224")]
    (
        Algorithm::Sha3_224,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
    ),
    #[cfg(feature = "sha3-256")]
    (
        Algorithm::Sha3_256,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    #[cfg(feature = "sha3-384")]
    (
        Algorithm::Sha3_384,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
         98d88cea927ac7f539f1edf228376d25",
    ),
    #[cfg(feature = "sha3-512")]
    (
        Algorithm::Sha3_512,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    ),
    #[cfg(feature = "keccak-224")]
    (
        Algorithm::Keccak224,
        "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
    ),
    #[cfg(feature = "keccak-256")]
    (
        Algorithm::Keccak256,
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    ),
    #[cfg(feature = "keccak-288")]
    (
        Algorithm::Keccak288,
        "20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc9\
         4289f4d6",
    ),
    #[cfg(feature = "keccak-384")]
    (
        Algorithm::Keccak384,
        "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99\
         f8c681e4afaf31a34db29fb763e3c28e",
    ),
    #[cfg(feature = "keccak-512")]
    (
        Algorithm::Keccak512,
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5\
         d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
    ),
    #[cfg(feature = "shake128")]
    (
        Algorithm::Shake128,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    ),
    #[cfg(feature = "shake256")]
    (
        Algorithm::Shake256,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
         d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
    ),
];

#[test]
fn every_enabled_digest_hashes_abc_to_its_published_value() {
    for (algorithm, expected) in ABC {
        assert_eq!(
            hex(&digest::calculate(*algorithm, b"abc")),
            *expected,
            "{algorithm:?}"
        );
    }
}

#[test]
fn the_list_holds_every_enabled_digest_once() {
    let listed: Vec<_> = digest::algorithms()
        .map(|entry| entry.algorithm())
        .collect();
    assert_eq!(listed.len(), ABC.len());
    for (algorithm, _) in ABC {
        assert_eq!(listed.iter().filter(|known| *known == algorithm).count(), 1);
    }
}

#[test]
fn feeding_the_input_in_pieces_gives_the_same_hash_as_one_call() {
    for entry in digest::algorithms() {
        let mut pieces = entry.create();
        pieces.update(b"a");
        assert_eq!(
            digest::do_final(&mut pieces, b"bc"),
            digest::calculate(entry.algorithm(), b"abc"),
            "{}",
            entry.name()
        );
    }
}

#[test]
fn every_listed_digest_is_found_again_by_its_name_in_any_case() {
    for entry in digest::algorithms() {
        for name in [entry.name().to_string(), entry.name().to_lowercase()] {
            assert_eq!(
                digest::get_by_name(&name).map(|found| found.algorithm()),
                Ok(entry.algorithm())
            );
        }
    }
}

#[test]
fn every_listed_oid_is_found_again_as_an_oid_and_as_dotted_text() {
    for entry in digest::algorithms() {
        let Some(oid) = entry.oid() else { continue };
        assert_eq!(
            digest::get_by_oid(&oid.oid()).map(|found| found.algorithm()),
            Ok(entry.algorithm())
        );
        assert_eq!(
            digest::get_by_name(oid.dotted()).map(|found| found.algorithm()),
            Ok(entry.algorithm())
        );
    }
}

#[test]
fn unknown_names_and_oids_are_rejected() {
    assert_eq!(
        digest::get_by_name("SHA3-1024").err(),
        Some(SecurityError::UnknownDigest)
    );
    assert_eq!(
        digest::get_by_name("1.2.3.4").err(),
        Some(SecurityError::UnknownDigest)
    );
    assert_eq!(
        digest::get_by_oid(&"1.2.3.4".parse().unwrap()).err(),
        Some(SecurityError::UnknownDigest)
    );
    assert_eq!(
        digest::calculate_by_name("unknown", b"abc"),
        Err(SecurityError::UnknownDigest)
    );
}

#[cfg(feature = "sha256")]
#[test]
fn the_name_and_oid_helpers_hash_like_calculate() {
    let expected = digest::calculate(Algorithm::Sha256, b"abc");
    assert_eq!(
        digest::calculate_by_name("sha-256", b"abc"),
        Ok(expected.clone())
    );
    let oid = "2.16.840.1.101.3.4.2.1".parse().unwrap();
    assert_eq!(digest::calculate_by_oid(&oid, b"abc"), Ok(expected));
}

#[cfg(feature = "sha256")]
#[test]
fn a_digest_displays_its_name() {
    assert_eq!(digest::get(Algorithm::Sha256).to_string(), "SHA-256");
}
