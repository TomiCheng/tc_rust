#[allow(unused_imports, reason = "所有 wrapper 的 feature 都關掉時，表是空的")]
use tc_asn1::NamedOid;

#[allow(unused_imports, reason = "所有 wrapper 的 feature 都關掉時，表是空的")]
use super::AnyWrapper;
use super::WrapEntry;

/// 每種 wrapper 一列；新增時在這裡加一列。
pub(super) const WRAPPERS: &[WrapEntry] = &[
    // RFC 3394。OID 照 BC：三種金鑰長度的 OID 都對到這一列，不限制 KEK 長度；
    // KEK 產生時 24 bytes（同 AES 的預設）。參數沒帶 IV 時用規格的 A6A6…
    #[cfg(feature = "aes")]
    WrapEntry::new(
        &["AESWRAP", "AESKW"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05],
                "2.16.840.1.101.3.4.1.5",
                "id-aes128-wrap",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19],
                "2.16.840.1.101.3.4.1.25",
                "id-aes192-wrap",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d],
                "2.16.840.1.101.3.4.1.45",
                "id-aes256-wrap",
            ),
        ],
        &[16, 24, 32],
        24,
        || AnyWrapper::new(tc_key_wrap::Rfc3394WrapEngine::new(tc_aes::AesEngine::new())),
    ),
    // RFC 3394 換成 ARIA。OID 照 BC 對到這一列；KEK 產生時 32 bytes（同 ARIA 的預設 256 bits）
    #[cfg(feature = "aria")]
    WrapEntry::new(
        &["ARIAWRAP", "ARIAKW"],
        &[
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x28],
                "1.2.410.200046.1.1.40",
                "id-aria128-kw",
            ),
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x29],
                "1.2.410.200046.1.1.41",
                "id-aria192-kw",
            ),
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2a],
                "1.2.410.200046.1.1.42",
                "id-aria256-kw",
            ),
        ],
        &[16, 24, 32],
        32,
        || {
            AnyWrapper::new(tc_key_wrap::Rfc3394WrapEngine::new(
                tc_aria::AriaEngine::new(),
            ))
        },
    ),
    // RFC 3657：RFC 3394 換成 Camellia。OID 照 BC 對到這一列；KEK 產生時 32 bytes（同 Camellia 的預設 256 bits）
    #[cfg(feature = "camellia")]
    WrapEntry::new(
        &["CAMELLIAWRAP"],
        &[
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x02,
                ],
                "1.2.392.200011.61.1.1.3.2",
                "id-camellia128-wrap",
            ),
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x03,
                ],
                "1.2.392.200011.61.1.1.3.3",
                "id-camellia192-wrap",
            ),
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x04,
                ],
                "1.2.392.200011.61.1.1.3.4",
                "id-camellia256-wrap",
            ),
        ],
        &[16, 24, 32],
        32,
        || {
            AnyWrapper::new(tc_key_wrap::Rfc3394WrapEngine::new(
                tc_camellia::CamelliaEngine::new(),
            ))
        },
    ),
];
