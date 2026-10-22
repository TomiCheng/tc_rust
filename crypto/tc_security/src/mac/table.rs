#[allow(unused_imports, reason = "所有 MAC 的 feature 都關掉時，表是空的")]
use tc_asn1::NamedOid;

#[allow(unused_imports, reason = "所有 MAC 的 feature 都關掉時，表是空的")]
use super::AnyMac;
use super::MacEntry;

/// 每種 MAC 一列；新增時在這裡加一列。
pub(super) const MACS: &[MacEntry] = &[
    // HMAC 照 BC 的 MacUtilities：每個 digest 一列，SHAKE 除外。金鑰長度不限，產生時跟 digest
    // 輸出一樣長（同 BC 的預設長度）。別名照 BC 的寫法：HMAC 與 digest 名稱之間可以是 `-`、`/`
    // 或什麼都沒有；OID 是 PKCS#5、NIST 與 IANA 的 HMAC OID，原始 Keccak 與 MD2、MD4 沒有
    #[cfg(feature = "md2")]
    MacEntry::new(
        &["HMAC-MD2", "HMAC/MD2", "HMACMD2"],
        &[],
        1,
        usize::MAX,
        16,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Md2,
            )))
        },
    ),
    #[cfg(feature = "md4")]
    MacEntry::new(
        &["HMAC-MD4", "HMAC/MD4", "HMACMD4"],
        &[],
        1,
        usize::MAX,
        16,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Md4,
            )))
        },
    ),
    #[cfg(feature = "md5")]
    MacEntry::new(
        &["HMAC-MD5", "HMAC/MD5", "HMACMD5"],
        &[NamedOid::new(
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x01],
            "1.3.6.1.5.5.8.1.1",
            "hmac-md5",
        )],
        1,
        usize::MAX,
        16,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Md5,
            )))
        },
    ),
    #[cfg(feature = "sha1")]
    MacEntry::new(
        &["HMAC-SHA1", "HMAC/SHA1", "HMACSHA1"],
        &[
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
        1,
        usize::MAX,
        20,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha1,
            )))
        },
    ),
    #[cfg(feature = "sha224")]
    MacEntry::new(
        &["HMAC-SHA224", "HMAC/SHA224", "HMACSHA224"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
            "1.2.840.113549.2.8",
            "id-hmacWithSHA224",
        )],
        1,
        usize::MAX,
        28,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha224,
            )))
        },
    ),
    #[cfg(feature = "sha256")]
    MacEntry::new(
        &["HMAC-SHA256", "HMAC/SHA256", "HMACSHA256"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
            "1.2.840.113549.2.9",
            "id-hmacWithSHA256",
        )],
        1,
        usize::MAX,
        32,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha256,
            )))
        },
    ),
    #[cfg(feature = "sha384")]
    MacEntry::new(
        &["HMAC-SHA384", "HMAC/SHA384", "HMACSHA384"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
            "1.2.840.113549.2.10",
            "id-hmacWithSHA384",
        )],
        1,
        usize::MAX,
        48,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha384,
            )))
        },
    ),
    #[cfg(feature = "sha512")]
    MacEntry::new(
        &["HMAC-SHA512", "HMAC/SHA512", "HMACSHA512"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
            "1.2.840.113549.2.11",
            "id-hmacWithSHA512",
        )],
        1,
        usize::MAX,
        64,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha512,
            )))
        },
    ),
    #[cfg(feature = "sha512-224")]
    MacEntry::new(
        &["HMAC-SHA512-224", "HMAC/SHA512-224", "HMACSHA512-224"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c],
            "1.2.840.113549.2.12",
            "id-hmacWithSHA512-224",
        )],
        1,
        usize::MAX,
        28,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha512_224,
            )))
        },
    ),
    #[cfg(feature = "sha512-256")]
    MacEntry::new(
        &["HMAC-SHA512-256", "HMAC/SHA512-256", "HMACSHA512-256"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d],
            "1.2.840.113549.2.13",
            "id-hmacWithSHA512-256",
        )],
        1,
        usize::MAX,
        32,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha512_256,
            )))
        },
    ),
    #[cfg(feature = "sha3-224")]
    MacEntry::new(
        &["HMAC-SHA3-224", "HMAC/SHA3-224", "HMACSHA3-224"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d],
            "2.16.840.1.101.3.4.2.13",
            "id-hmacWithSHA3-224",
        )],
        1,
        usize::MAX,
        28,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha3_224,
            )))
        },
    ),
    #[cfg(feature = "sha3-256")]
    MacEntry::new(
        &["HMAC-SHA3-256", "HMAC/SHA3-256", "HMACSHA3-256"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e],
            "2.16.840.1.101.3.4.2.14",
            "id-hmacWithSHA3-256",
        )],
        1,
        usize::MAX,
        32,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha3_256,
            )))
        },
    ),
    #[cfg(feature = "sha3-384")]
    MacEntry::new(
        &["HMAC-SHA3-384", "HMAC/SHA3-384", "HMACSHA3-384"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f],
            "2.16.840.1.101.3.4.2.15",
            "id-hmacWithSHA3-384",
        )],
        1,
        usize::MAX,
        48,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha3_384,
            )))
        },
    ),
    #[cfg(feature = "sha3-512")]
    MacEntry::new(
        &["HMAC-SHA3-512", "HMAC/SHA3-512", "HMACSHA3-512"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10],
            "2.16.840.1.101.3.4.2.16",
            "id-hmacWithSHA3-512",
        )],
        1,
        usize::MAX,
        64,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha3_512,
            )))
        },
    ),
    #[cfg(feature = "keccak-224")]
    MacEntry::new(
        &["HMAC-KECCAK224", "HMAC/KECCAK224", "HMACKECCAK224"],
        &[],
        1,
        usize::MAX,
        28,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Keccak224,
            )))
        },
    ),
    #[cfg(feature = "keccak-256")]
    MacEntry::new(
        &["HMAC-KECCAK256", "HMAC/KECCAK256", "HMACKECCAK256"],
        &[],
        1,
        usize::MAX,
        32,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Keccak256,
            )))
        },
    ),
    #[cfg(feature = "keccak-288")]
    MacEntry::new(
        &["HMAC-KECCAK288", "HMAC/KECCAK288", "HMACKECCAK288"],
        &[],
        1,
        usize::MAX,
        36,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Keccak288,
            )))
        },
    ),
    #[cfg(feature = "keccak-384")]
    MacEntry::new(
        &["HMAC-KECCAK384", "HMAC/KECCAK384", "HMACKECCAK384"],
        &[],
        1,
        usize::MAX,
        48,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Keccak384,
            )))
        },
    ),
    #[cfg(feature = "keccak-512")]
    MacEntry::new(
        &["HMAC-KECCAK512", "HMAC/KECCAK512", "HMACKECCAK512"],
        &[],
        1,
        usize::MAX,
        64,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Keccak512,
            )))
        },
    ),
    // CBC-MAC 套在 RC2 上，tag 同 BC 是半個區塊（4 bytes），最後不滿一塊時補零。
    // 金鑰 1 到 128 bytes，產生時 16 bytes（同 BC 的 128 bits）；參數沒帶 IV 時同 BC 用全零的 8 bytes
    #[cfg(feature = "rc2")]
    MacEntry::new(
        &["RC2MAC", "RC2"],
        &[],
        1,
        tc_rc_cipher::RC2_MAX_KEY_BYTES,
        16,
        || {
            AnyMac::new(super::ZeroIv::new(
                tc_macs::CbcMac::new(tc_rc_cipher::Rc2Engine::new()),
                8,
            ))
        },
    ),
];
