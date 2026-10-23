//! BC `PbeUtilities` 的方案，只列出 cipher 已經接上的：缺 RC4（`PBEWITHSHAAND128BITRC4`、
//! `PBEWITHSHAAND40BITRC4`）、IDEA 與 Twofish 的方案，以及 PBES2 與 `PBEWITHHMAC…` 的 MAC 方案。
//! 金鑰與 IV 的長度照 BC 的 `GenerateCipherParameters`；DES 與 DESede 的金鑰另外設 odd parity。

#[allow(unused_imports, reason = "沒開對應的 digest 與 cipher 時，表是空的")]
use tc_asn1::NamedOid;

use super::PbeEntry;
#[allow(unused_imports, reason = "沒開對應的 digest 與 cipher 時，表是空的")]
use super::pbe_entry::Scheme;
#[allow(unused_imports, reason = "沒開對應的 digest 與 cipher 時，表是空的")]
use crate::digest::Algorithm;

pub(super) const SCHEMES: &[PbeEntry] = &[
    #[cfg(all(feature = "md2", feature = "des"))]
    PbeEntry::new(
        &["PBEWITHMD2ANDDES-CBC"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x01],
            "1.2.840.113549.1.5.1",
            "pbeWithMD2AndDES-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Md2,
        "DES/CBC/PKCS7PADDING",
        8,
        8,
        true,
    ),
    #[cfg(all(feature = "md2", feature = "rc2"))]
    PbeEntry::new(
        &["PBEWITHMD2ANDRC2-CBC"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x04],
            "1.2.840.113549.1.5.4",
            "pbeWithMD2AndRC2-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Md2,
        "RC2/CBC/PKCS7PADDING",
        8,
        8,
        false,
    ),
    #[cfg(all(feature = "md5", feature = "des"))]
    PbeEntry::new(
        &["PBEWITHMD5ANDDES-CBC"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03],
            "1.2.840.113549.1.5.3",
            "pbeWithMD5AndDES-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Md5,
        "DES/CBC/PKCS7PADDING",
        8,
        8,
        true,
    ),
    #[cfg(all(feature = "md5", feature = "rc2"))]
    PbeEntry::new(
        &["PBEWITHMD5ANDRC2-CBC"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x06],
            "1.2.840.113549.1.5.6",
            "pbeWithMD5AndRC2-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Md5,
        "RC2/CBC/PKCS7PADDING",
        8,
        8,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "des"))]
    PbeEntry::new(
        &[
            "PBEWITHSHA1ANDDES-CBC",
            "PBEWITHSHA1ANDDES",
            "PBEWITHSHA-1ANDDES",
            "PBEWITHSHA-1ANDDES-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a],
            "1.2.840.113549.1.5.10",
            "pbeWithSHA1AndDES-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Sha1,
        "DES/CBC/PKCS7PADDING",
        8,
        8,
        true,
    ),
    #[cfg(all(feature = "sha1", feature = "rc2"))]
    PbeEntry::new(
        &[
            "PBEWITHSHA1ANDRC2-CBC",
            "PBEWITHSHA1ANDRC2",
            "PBEWITHSHA-1ANDRC2",
            "PBEWITHSHA-1ANDRC2-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0b],
            "1.2.840.113549.1.5.11",
            "pbeWithSHA1AndRC2-CBC",
        )],
        Scheme::Pkcs5S1,
        Algorithm::Sha1,
        "RC2/CBC/PKCS7PADDING",
        8,
        8,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "desede"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND3-KEYTRIPLEDES-CBC",
            "PBEWITHSHAAND3-KEYDESEDE-CBC",
            "PBEWITHSHA1AND3-KEYDESEDE-CBC",
            "PBEWITHSHA1AND3-KEYTRIPLEDES-CBC",
            "PBEWITHSHA-1AND3-KEYDESEDE-CBC",
            "PBEWITHSHA-1AND3-KEYTRIPLEDES-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03],
            "1.2.840.113549.1.12.1.3",
            "pbeWithSHAAnd3-KeyTripleDES-CBC",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "DESEDE/CBC/PKCS7PADDING",
        24,
        8,
        true,
    ),
    #[cfg(all(feature = "sha1", feature = "desede"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",
            "PBEWITHSHAAND2-KEYDESEDE-CBC",
            "PBEWITHSHA1AND2-KEYDESEDE-CBC",
            "PBEWITHSHA1AND2-KEYTRIPLEDES-CBC",
            "PBEWITHSHA-1AND2-KEYDESEDE-CBC",
            "PBEWITHSHA-1AND2-KEYTRIPLEDES-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x04],
            "1.2.840.113549.1.12.1.4",
            "pbeWithSHAAnd2-KeyTripleDES-CBC",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "DESEDE/CBC/PKCS7PADDING",
        16,
        8,
        true,
    ),
    #[cfg(all(feature = "sha1", feature = "rc2"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND128BITRC2-CBC",
            "PBEWITHSHA1AND128BITRC2-CBC",
            "PBEWITHSHA-1AND128BITRC2-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05],
            "1.2.840.113549.1.12.1.5",
            "pbeWithSHAAnd128BitRC2-CBC",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "RC2/CBC/PKCS7PADDING",
        16,
        8,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "rc2"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND40BITRC2-CBC",
            "PBEWITHSHA1AND40BITRC2-CBC",
            "PBEWITHSHA-1AND40BITRC2-CBC",
        ],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06],
            "1.2.840.113549.1.12.1.6",
            "pbewithSHAAnd40BitRC2-CBC",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "RC2/CBC/PKCS7PADDING",
        5,
        8,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND128BITAES-CBC-BC",
            "PBEWITHSHA1AND128BITAES-CBC-BC",
            "PBEWITHSHA-1AND128BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x01, 0x02, 0x01, 0x02,
            ],
            "1.3.6.1.4.1.22554.1.1.2.1.2",
            "bc-pbe-sha1-pkcs12-aes128-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "AES/CBC/PKCS7PADDING",
        16,
        16,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND192BITAES-CBC-BC",
            "PBEWITHSHA1AND192BITAES-CBC-BC",
            "PBEWITHSHA-1AND192BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x01, 0x02, 0x01, 0x16,
            ],
            "1.3.6.1.4.1.22554.1.1.2.1.22",
            "bc-pbe-sha1-pkcs12-aes192-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "AES/CBC/PKCS7PADDING",
        24,
        16,
        false,
    ),
    #[cfg(all(feature = "sha1", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHAAND256BITAES-CBC-BC",
            "PBEWITHSHA1AND256BITAES-CBC-BC",
            "PBEWITHSHA-1AND256BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x01, 0x02, 0x01, 0x2a,
            ],
            "1.3.6.1.4.1.22554.1.1.2.1.42",
            "bc-pbe-sha1-pkcs12-aes256-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha1,
        "AES/CBC/PKCS7PADDING",
        32,
        16,
        false,
    ),
    #[cfg(all(feature = "sha256", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHA256AND128BITAES-CBC-BC",
            "PBEWITHSHA-256AND128BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            ],
            "1.3.6.1.4.1.22554.1.2.1.2.1.2",
            "bc-pbe-sha256-pkcs12-aes128-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha256,
        "AES/CBC/PKCS7PADDING",
        16,
        16,
        false,
    ),
    #[cfg(all(feature = "sha256", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHA256AND192BITAES-CBC-BC",
            "PBEWITHSHA-256AND192BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x02, 0x01, 0x02, 0x01, 0x16,
            ],
            "1.3.6.1.4.1.22554.1.2.1.2.1.22",
            "bc-pbe-sha256-pkcs12-aes192-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha256,
        "AES/CBC/PKCS7PADDING",
        24,
        16,
        false,
    ),
    #[cfg(all(feature = "sha256", feature = "aes"))]
    PbeEntry::new(
        &[
            "PBEWITHSHA256AND256BITAES-CBC-BC",
            "PBEWITHSHA-256AND256BITAES-CBC-BC",
        ],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb0, 0x1a, 0x01, 0x02, 0x01, 0x02, 0x01, 0x2a,
            ],
            "1.3.6.1.4.1.22554.1.2.1.2.1.42",
            "bc-pbe-sha256-pkcs12-aes256-cbc",
        )],
        Scheme::Pkcs12,
        Algorithm::Sha256,
        "AES/CBC/PKCS7PADDING",
        32,
        16,
        false,
    ),
    #[cfg(all(feature = "md5", feature = "aes"))]
    PbeEntry::new(
        &["PBEWITHMD5AND128BITAES-CBC-OPENSSL"],
        &[],
        Scheme::OpenSsl,
        Algorithm::Md5,
        "AES/CBC/PKCS7PADDING",
        16,
        16,
        false,
    ),
    #[cfg(all(feature = "md5", feature = "aes"))]
    PbeEntry::new(
        &["PBEWITHMD5AND192BITAES-CBC-OPENSSL"],
        &[],
        Scheme::OpenSsl,
        Algorithm::Md5,
        "AES/CBC/PKCS7PADDING",
        24,
        16,
        false,
    ),
    #[cfg(all(feature = "md5", feature = "aes"))]
    PbeEntry::new(
        &["PBEWITHMD5AND256BITAES-CBC-OPENSSL"],
        &[],
        Scheme::OpenSsl,
        Algorithm::Md5,
        "AES/CBC/PKCS7PADDING",
        32,
        16,
        false,
    ),
];
