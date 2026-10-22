#[allow(unused_imports, reason = "所有 digest 的 feature 都關掉時，表是空的")]
use tc_asn1::NamedOid;

#[allow(unused_imports, reason = "所有 digest 的 feature 都關掉時，表是空的")]
use super::Algorithm;
use super::DigestEntry;

/// 每個 digest 一列；新增演算法只要在這裡加一列。
pub(super) const DIGESTS: &[DigestEntry] = &[
    #[cfg(feature = "md2")]
    DigestEntry::new(
        Algorithm::Md2,
        "MD2",
        Some(NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02],
            "1.2.840.113549.2.2",
            "md2",
        )),
        || Box::new(tc_md::Md2Digest::new()),
    ),
    #[cfg(feature = "md4")]
    DigestEntry::new(
        Algorithm::Md4,
        "MD4",
        Some(NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04],
            "1.2.840.113549.2.4",
            "md4",
        )),
        || Box::new(tc_md::Md4Digest::new()),
    ),
    #[cfg(feature = "md5")]
    DigestEntry::new(
        Algorithm::Md5,
        "MD5",
        Some(NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05],
            "1.2.840.113549.2.5",
            "md5",
        )),
        || Box::new(tc_md::Md5Digest::new()),
    ),
    #[cfg(feature = "sha1")]
    DigestEntry::new(
        Algorithm::Sha1,
        "SHA-1",
        Some(NamedOid::new(
            &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
            "1.3.14.3.2.26",
            "id-sha1",
        )),
        || Box::new(tc_sha::Sha1Digest::new()),
    ),
    #[cfg(feature = "sha224")]
    DigestEntry::new(
        Algorithm::Sha224,
        "SHA-224",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
            "2.16.840.1.101.3.4.2.4",
            "id-sha224",
        )),
        || Box::new(tc_sha::Sha224Digest::new()),
    ),
    #[cfg(feature = "sha256")]
    DigestEntry::new(
        Algorithm::Sha256,
        "SHA-256",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            "2.16.840.1.101.3.4.2.1",
            "id-sha256",
        )),
        || Box::new(tc_sha::Sha256Digest::new()),
    ),
    #[cfg(feature = "sha384")]
    DigestEntry::new(
        Algorithm::Sha384,
        "SHA-384",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            "2.16.840.1.101.3.4.2.2",
            "id-sha384",
        )),
        || Box::new(tc_sha::Sha384Digest::new()),
    ),
    #[cfg(feature = "sha512")]
    DigestEntry::new(
        Algorithm::Sha512,
        "SHA-512",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            "2.16.840.1.101.3.4.2.3",
            "id-sha512",
        )),
        || Box::new(tc_sha::Sha512Digest::new()),
    ),
    #[cfg(feature = "sha512-224")]
    DigestEntry::new(
        Algorithm::Sha512_224,
        "SHA-512/224",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
            "2.16.840.1.101.3.4.2.5",
            "id-sha512-224",
        )),
        || Box::new(tc_sha::Sha512tDigest::new(224)),
    ),
    #[cfg(feature = "sha512-256")]
    DigestEntry::new(
        Algorithm::Sha512_256,
        "SHA-512/256",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
            "2.16.840.1.101.3.4.2.6",
            "id-sha512-256",
        )),
        || Box::new(tc_sha::Sha512tDigest::new(256)),
    ),
    // FIPS 202；原始 Keccak 沒有 OID。SHAKE 當固定長度的 digest，名稱與長度同 BC
    #[cfg(feature = "sha3-224")]
    DigestEntry::new(
        Algorithm::Sha3_224,
        "SHA3-224",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            "2.16.840.1.101.3.4.2.7",
            "id-sha3-224",
        )),
        || Box::new(tc_keccak::Sha3Digest::new(224)),
    ),
    #[cfg(feature = "sha3-256")]
    DigestEntry::new(
        Algorithm::Sha3_256,
        "SHA3-256",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            "2.16.840.1.101.3.4.2.8",
            "id-sha3-256",
        )),
        || Box::new(tc_keccak::Sha3Digest::new(256)),
    ),
    #[cfg(feature = "sha3-384")]
    DigestEntry::new(
        Algorithm::Sha3_384,
        "SHA3-384",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            "2.16.840.1.101.3.4.2.9",
            "id-sha3-384",
        )),
        || Box::new(tc_keccak::Sha3Digest::new(384)),
    ),
    #[cfg(feature = "sha3-512")]
    DigestEntry::new(
        Algorithm::Sha3_512,
        "SHA3-512",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
            "2.16.840.1.101.3.4.2.10",
            "id-sha3-512",
        )),
        || Box::new(tc_keccak::Sha3Digest::new(512)),
    ),
    #[cfg(feature = "keccak-224")]
    DigestEntry::new(Algorithm::Keccak224, "KECCAK-224", None, || {
        Box::new(tc_keccak::KeccakDigest::new(224))
    }),
    #[cfg(feature = "keccak-256")]
    DigestEntry::new(Algorithm::Keccak256, "KECCAK-256", None, || {
        Box::new(tc_keccak::KeccakDigest::new(256))
    }),
    #[cfg(feature = "keccak-288")]
    DigestEntry::new(Algorithm::Keccak288, "KECCAK-288", None, || {
        Box::new(tc_keccak::KeccakDigest::new(288))
    }),
    #[cfg(feature = "keccak-384")]
    DigestEntry::new(Algorithm::Keccak384, "KECCAK-384", None, || {
        Box::new(tc_keccak::KeccakDigest::new(384))
    }),
    #[cfg(feature = "keccak-512")]
    DigestEntry::new(Algorithm::Keccak512, "KECCAK-512", None, || {
        Box::new(tc_keccak::KeccakDigest::new(512))
    }),
    #[cfg(feature = "shake128")]
    DigestEntry::new(
        Algorithm::Shake128,
        "SHAKE128-256",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            "2.16.840.1.101.3.4.2.11",
            "id-shake128",
        )),
        || Box::new(tc_keccak::ShakeDigest::new(128)),
    ),
    #[cfg(feature = "shake256")]
    DigestEntry::new(
        Algorithm::Shake256,
        "SHAKE256-512",
        Some(NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
            "2.16.840.1.101.3.4.2.12",
            "id-shake256",
        )),
        || Box::new(tc_keccak::ShakeDigest::new(256)),
    ),
];
