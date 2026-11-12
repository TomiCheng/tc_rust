#[allow(
    unused_imports,
    reason = "the table is empty when every key wrap feature is off"
)]
use tc_asn1::NamedOid;

use super::WrapEntry;
#[allow(
    unused_imports,
    reason = "the table is empty when every key wrap feature is off"
)]
use super::dyn_wrapper::Mapped;
#[allow(
    unused_imports,
    reason = "the table is empty when every key wrap feature is off"
)]
use crate::need::Need::{Optional, Required};

// RFC 3394 and RFC 5649 take an optional IV
#[allow(
    unused_macros,
    reason = "unused when none of its ciphers' features is on"
)]
macro_rules! rfc3394 {
    ($cipher:expr) => {
        Box::new(Mapped::iv_optional(tc_key_wrap::Rfc3394WrapEngine::new(
            $cipher,
        )))
    };
}

#[allow(
    unused_macros,
    reason = "unused when none of its ciphers' features is on"
)]
macro_rules! rfc5649 {
    ($cipher:expr) => {
        Box::new(Mapped::iv_optional(tc_key_wrap::Rfc5649WrapEngine::new(
            $cipher,
        )))
    };
}

// RFC 3211 needs an IV and pads with random bytes, from the operating system
#[allow(
    unused_macros,
    reason = "unused when none of its ciphers' features is on"
)]
macro_rules! rfc3211 {
    ($cipher:expr) => {
        Box::new(Mapped::iv_required(tc_key_wrap::Rfc3211WrapEngine::new(
            $cipher,
            rand_core::UnwrapErr(rand::rngs::SysRng),
        )))
    };
}

// One row per wrapper, with the names, aliases and OIDs of Bouncy Castle's WrapperUtilities: every
// key length's OID finds its row, and the row takes any key length the cipher does. A row needs the
// feature of its kind of wrap and that of its cipher
pub(super) const WRAPPERS: &[WrapEntry] = &[
    // RFC 3394. The IV, 8 bytes, replaces the one of the standard
    #[cfg(all(feature = "rfc3394-wrap", feature = "aes"))]
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
        Optional,
        || rfc3394!(tc_aes::AesEngine::new()),
    ),
    #[cfg(all(feature = "rfc3394-wrap", feature = "aria"))]
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
        Optional,
        || rfc3394!(tc_aria::AriaEngine::new()),
    ),
    #[cfg(all(feature = "rfc3394-wrap", feature = "camellia"))]
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
        Optional,
        || rfc3394!(tc_camellia::CamelliaEngine::new()),
    ),
    #[cfg(all(feature = "rfc3394-wrap", feature = "seed"))]
    WrapEntry::new(
        &["SEEDWRAP", "SEEDKW"],
        &[NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x07, 0x01, 0x01, 0x01],
            "1.2.410.200004.7.1.1.1",
            "id-npki-app-cmsSeed-wrap",
        )],
        Optional,
        || rfc3394!(tc_seed::SeedEngine::new()),
    ),
    // RFC 5649, which takes a key of any length. The IV, 4 bytes, replaces the one of the standard
    #[cfg(all(feature = "rfc5649-wrap", feature = "aes"))]
    WrapEntry::new(
        &["AESWRAPPAD", "AESKWP", "AESRFC5649WRAP"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x08],
                "2.16.840.1.101.3.4.1.8",
                "id-aes128-wrap-pad",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x1c],
                "2.16.840.1.101.3.4.1.28",
                "id-aes192-wrap-pad",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x30],
                "2.16.840.1.101.3.4.1.48",
                "id-aes256-wrap-pad",
            ),
        ],
        Optional,
        || rfc5649!(tc_aes::AesEngine::new()),
    ),
    #[cfg(all(feature = "rfc5649-wrap", feature = "aria"))]
    WrapEntry::new(
        &["ARIAWRAPPAD", "ARIAKWP"],
        &[
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2b],
                "1.2.410.200046.1.1.43",
                "id-aria128-kwp",
            ),
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2c],
                "1.2.410.200046.1.1.44",
                "id-aria192-kwp",
            ),
            NamedOid::new(
                &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2d],
                "1.2.410.200046.1.1.45",
                "id-aria256-kwp",
            ),
        ],
        Optional,
        || rfc5649!(tc_aria::AriaEngine::new()),
    ),
    // RFC 3211, which needs an IV of one block, and whose output differs each time
    #[cfg(all(feature = "rfc3211-wrap", feature = "aes"))]
    WrapEntry::new(&["AESRFC3211WRAP"], &[], Required, || {
        rfc3211!(tc_aes::AesEngine::new())
    }),
    #[cfg(all(feature = "rfc3211-wrap", feature = "aria"))]
    WrapEntry::new(&["ARIARFC3211WRAP"], &[], Required, || {
        rfc3211!(tc_aria::AriaEngine::new())
    }),
    #[cfg(all(feature = "rfc3211-wrap", feature = "camellia"))]
    WrapEntry::new(&["CAMELLIARFC3211WRAP"], &[], Required, || {
        rfc3211!(tc_camellia::CamelliaEngine::new())
    }),
    #[cfg(all(feature = "rfc3211-wrap", feature = "des"))]
    WrapEntry::new(&["DESRFC3211WRAP"], &[], Required, || {
        rfc3211!(tc_des::DesEngine::new())
    }),
    #[cfg(all(feature = "rfc3211-wrap", feature = "desede"))]
    WrapEntry::new(&["DESEDERFC3211WRAP"], &[], Required, || {
        rfc3211!(tc_des::DesEdeEngine::new())
    }),
];
