use tc_asn1::NamedOid;

use super::{no_key_pair, plain_key};
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 128 | 192 | 256,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

/// 沒寫長度時產生 256 bits，同 BC。
pub(super) const ARIA: GeneratorEntry = GeneratorEntry::new(
    &["ARIA"],
    &[],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 128 bits。OID 照 BC：這個長度的各個模式（含 BC 有、這裡沒有的 OCB2）與 key wrap 都對到這一列。
pub(super) const ARIA128: GeneratorEntry = GeneratorEntry::new(
    &["ARIA128"],
    &[
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x02],
            "1.2.410.200046.1.1.2",
            "aria128-cbc",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x25],
            "1.2.410.200046.1.1.37",
            "aria128-ccm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x03],
            "1.2.410.200046.1.1.3",
            "aria128-cfb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x05],
            "1.2.410.200046.1.1.5",
            "aria128-ctr",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x01],
            "1.2.410.200046.1.1.1",
            "aria128-ecb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x22],
            "1.2.410.200046.1.1.34",
            "aria128-gcm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x28],
            "1.2.410.200046.1.1.40",
            "id-aria128-kw",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2b],
            "1.2.410.200046.1.1.43",
            "id-aria128-kwp",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x1f],
            "1.2.410.200046.1.1.31",
            "aria128-ocb2",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x04],
            "1.2.410.200046.1.1.4",
            "aria128-ofb",
        ),
    ],
    KeyGenParams::Basic { strength: 128 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 192 bits。
pub(super) const ARIA192: GeneratorEntry = GeneratorEntry::new(
    &["ARIA192"],
    &[
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x07],
            "1.2.410.200046.1.1.7",
            "aria192-cbc",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x26],
            "1.2.410.200046.1.1.38",
            "aria192-ccm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x08],
            "1.2.410.200046.1.1.8",
            "aria192-cfb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0a],
            "1.2.410.200046.1.1.10",
            "aria192-ctr",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x06],
            "1.2.410.200046.1.1.6",
            "aria192-ecb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x23],
            "1.2.410.200046.1.1.35",
            "aria192-gcm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x29],
            "1.2.410.200046.1.1.41",
            "id-aria192-kw",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2c],
            "1.2.410.200046.1.1.44",
            "id-aria192-kwp",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x20],
            "1.2.410.200046.1.1.32",
            "aria192-ocb2",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x09],
            "1.2.410.200046.1.1.9",
            "aria192-ofb",
        ),
    ],
    KeyGenParams::Basic { strength: 192 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 256 bits。
pub(super) const ARIA256: GeneratorEntry = GeneratorEntry::new(
    &["ARIA256"],
    &[
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0c],
            "1.2.410.200046.1.1.12",
            "aria256-cbc",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x27],
            "1.2.410.200046.1.1.39",
            "aria256-ccm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0d],
            "1.2.410.200046.1.1.13",
            "aria256-cfb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0f],
            "1.2.410.200046.1.1.15",
            "aria256-ctr",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0b],
            "1.2.410.200046.1.1.11",
            "aria256-ecb",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x24],
            "1.2.410.200046.1.1.36",
            "aria256-gcm",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2a],
            "1.2.410.200046.1.1.42",
            "id-aria256-kw",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2d],
            "1.2.410.200046.1.1.45",
            "id-aria256-kwp",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x21],
            "1.2.410.200046.1.1.33",
            "aria256-ocb2",
        ),
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0e],
            "1.2.410.200046.1.1.14",
            "aria256-ofb",
        ),
    ],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    plain_key,
    no_key_pair,
);
