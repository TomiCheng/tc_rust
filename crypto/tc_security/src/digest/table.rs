#[allow(unused_imports, reason = "所有 digest 的 feature 都關掉時，表是空的")]
use tc_asn1::NamedOid;

#[allow(unused_imports, reason = "所有 digest 的 feature 都關掉時，表是空的")]
use super::Algorithm;
use super::DigestEntry;

/// 每個 digest 一列；新增演算法只要在這裡加一列。名稱、別名與 OID 照 BC 的 `DigestUtilities`：
/// 第一個名稱是正式名稱，第一個 OID 是 digest 本身的（DigestInfo 用它），其餘照 BC 也對到這一列，
/// 包括 HMAC 的 OID。原始 Keccak 沒有 OID；SHAKE 當固定長度的 digest，名稱與長度同 BC。
pub(super) const DIGESTS: &[DigestEntry] = &[
    #[cfg(feature = "md2")]
    DigestEntry::new(
        Algorithm::Md2,
        &["MD2"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02],
            "1.2.840.113549.2.2",
            "md2",
        )],
        || Box::new(tc_md::Md2Digest::new()),
    ),
    #[cfg(feature = "md4")]
    DigestEntry::new(
        Algorithm::Md4,
        &["MD4"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04],
            "1.2.840.113549.2.4",
            "md4",
        )],
        || Box::new(tc_md::Md4Digest::new()),
    ),
    #[cfg(feature = "md5")]
    DigestEntry::new(
        Algorithm::Md5,
        &["MD5"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05],
            "1.2.840.113549.2.5",
            "md5",
        )],
        || Box::new(tc_md::Md5Digest::new()),
    ),
    #[cfg(feature = "sha1")]
    DigestEntry::new(
        Algorithm::Sha1,
        &["SHA-1", "SHA1"],
        &[
            NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "id-sha1"),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
                "1.2.840.113549.2.7",
                "id-hmacWithSHA1",
            ),
            NamedOid::new(
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02],
                "1.3.6.1.5.5.8.1.2",
                "hmac-sha1",
            ),
        ],
        || Box::new(tc_sha::Sha1Digest::new()),
    ),
    #[cfg(feature = "sha224")]
    DigestEntry::new(
        Algorithm::Sha224,
        &["SHA-224", "SHA224"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
                "2.16.840.1.101.3.4.2.4",
                "id-sha224",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
                "1.2.840.113549.2.8",
                "id-hmacWithSHA224",
            ),
        ],
        || Box::new(tc_sha::Sha224Digest::new()),
    ),
    #[cfg(feature = "sha256")]
    DigestEntry::new(
        Algorithm::Sha256,
        &["SHA-256", "SHA256"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                "2.16.840.1.101.3.4.2.1",
                "id-sha256",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
                "1.2.840.113549.2.9",
                "id-hmacWithSHA256",
            ),
        ],
        || Box::new(tc_sha::Sha256Digest::new()),
    ),
    #[cfg(feature = "sha384")]
    DigestEntry::new(
        Algorithm::Sha384,
        &["SHA-384", "SHA384"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
                "2.16.840.1.101.3.4.2.2",
                "id-sha384",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
                "1.2.840.113549.2.10",
                "id-hmacWithSHA384",
            ),
        ],
        || Box::new(tc_sha::Sha384Digest::new()),
    ),
    #[cfg(feature = "sha512")]
    DigestEntry::new(
        Algorithm::Sha512,
        &["SHA-512", "SHA512"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
                "2.16.840.1.101.3.4.2.3",
                "id-sha512",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
                "1.2.840.113549.2.11",
                "id-hmacWithSHA512",
            ),
        ],
        || Box::new(tc_sha::Sha512Digest::new()),
    ),
    #[cfg(feature = "sha512-224")]
    DigestEntry::new(
        Algorithm::Sha512_224,
        &[
            "SHA-512/224",
            "SHA512/224",
            "SHA512-224",
            "SHA512(224)",
            "SHA-512(224)",
        ],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
                "2.16.840.1.101.3.4.2.5",
                "id-sha512-224",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c],
                "1.2.840.113549.2.12",
                "id-hmacWithSHA512-224",
            ),
        ],
        || Box::new(tc_sha::Sha512tDigest::new(224)),
    ),
    #[cfg(feature = "sha512-256")]
    DigestEntry::new(
        Algorithm::Sha512_256,
        &[
            "SHA-512/256",
            "SHA512/256",
            "SHA512-256",
            "SHA512(256)",
            "SHA-512(256)",
        ],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
                "2.16.840.1.101.3.4.2.6",
                "id-sha512-256",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d],
                "1.2.840.113549.2.13",
                "id-hmacWithSHA512-256",
            ),
        ],
        || Box::new(tc_sha::Sha512tDigest::new(256)),
    ),
    #[cfg(feature = "sha3-224")]
    DigestEntry::new(
        Algorithm::Sha3_224,
        &["SHA3-224"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
                "2.16.840.1.101.3.4.2.7",
                "id-sha3-224",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d],
                "2.16.840.1.101.3.4.2.13",
                "id-hmacWithSHA3-224",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(224)),
    ),
    #[cfg(feature = "sha3-256")]
    DigestEntry::new(
        Algorithm::Sha3_256,
        &["SHA3-256"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
                "2.16.840.1.101.3.4.2.8",
                "id-sha3-256",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e],
                "2.16.840.1.101.3.4.2.14",
                "id-hmacWithSHA3-256",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(256)),
    ),
    #[cfg(feature = "sha3-384")]
    DigestEntry::new(
        Algorithm::Sha3_384,
        &["SHA3-384"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
                "2.16.840.1.101.3.4.2.9",
                "id-sha3-384",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f],
                "2.16.840.1.101.3.4.2.15",
                "id-hmacWithSHA3-384",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(384)),
    ),
    #[cfg(feature = "sha3-512")]
    DigestEntry::new(
        Algorithm::Sha3_512,
        &["SHA3-512"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
                "2.16.840.1.101.3.4.2.10",
                "id-sha3-512",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10],
                "2.16.840.1.101.3.4.2.16",
                "id-hmacWithSHA3-512",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(512)),
    ),
    #[cfg(feature = "keccak-224")]
    DigestEntry::new(
        Algorithm::Keccak224,
        &["KECCAK-224", "KECCAK224"],
        &[],
        || Box::new(tc_keccak::KeccakDigest::new(224)),
    ),
    #[cfg(feature = "keccak-256")]
    DigestEntry::new(
        Algorithm::Keccak256,
        &["KECCAK-256", "KECCAK256"],
        &[],
        || Box::new(tc_keccak::KeccakDigest::new(256)),
    ),
    #[cfg(feature = "keccak-288")]
    DigestEntry::new(
        Algorithm::Keccak288,
        &["KECCAK-288", "KECCAK288"],
        &[],
        || Box::new(tc_keccak::KeccakDigest::new(288)),
    ),
    #[cfg(feature = "keccak-384")]
    DigestEntry::new(
        Algorithm::Keccak384,
        &["KECCAK-384", "KECCAK384"],
        &[],
        || Box::new(tc_keccak::KeccakDigest::new(384)),
    ),
    #[cfg(feature = "keccak-512")]
    DigestEntry::new(
        Algorithm::Keccak512,
        &["KECCAK-512", "KECCAK512"],
        &[],
        || Box::new(tc_keccak::KeccakDigest::new(512)),
    ),
    #[cfg(feature = "shake128")]
    DigestEntry::new(
        Algorithm::Shake128,
        &["SHAKE128-256", "SHAKE128", "SHAKE-128"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            "2.16.840.1.101.3.4.2.11",
            "id-shake128",
        )],
        || Box::new(tc_keccak::ShakeDigest::new(128)),
    ),
    #[cfg(feature = "shake256")]
    DigestEntry::new(
        Algorithm::Shake256,
        &["SHAKE256-512", "SHAKE256", "SHAKE-256"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
            "2.16.840.1.101.3.4.2.12",
            "id-shake256",
        )],
        || Box::new(tc_keccak::ShakeDigest::new(256)),
    ),
];
