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

/// 沒寫長度時產生 256 bits，同 BC；BC 的 `CAMELLIAWRAP` 也對到這一列。
pub(super) const CAMELLIA: GeneratorEntry = GeneratorEntry::new(
    &["CAMELLIA", "CAMELLIAWRAP"],
    &[],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 128 bits。OID 照 BC：這個長度的 CBC 與 key wrap 都對到這一列。
pub(super) const CAMELLIA128: GeneratorEntry = GeneratorEntry::new(
    &["CAMELLIA128"],
    &[
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x02,
            ],
            "1.2.392.200011.61.1.1.1.2",
            "id-camellia128-cbc",
        ),
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x02,
            ],
            "1.2.392.200011.61.1.1.3.2",
            "id-camellia128-wrap",
        ),
    ],
    KeyGenParams::Basic { strength: 128 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 192 bits。
pub(super) const CAMELLIA192: GeneratorEntry = GeneratorEntry::new(
    &["CAMELLIA192"],
    &[
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x03,
            ],
            "1.2.392.200011.61.1.1.1.3",
            "id-camellia192-cbc",
        ),
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x03,
            ],
            "1.2.392.200011.61.1.1.3.3",
            "id-camellia192-wrap",
        ),
    ],
    KeyGenParams::Basic { strength: 192 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 256 bits。
pub(super) const CAMELLIA256: GeneratorEntry = GeneratorEntry::new(
    &["CAMELLIA256"],
    &[
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x04,
            ],
            "1.2.392.200011.61.1.1.1.4",
            "id-camellia256-cbc",
        ),
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x04,
            ],
            "1.2.392.200011.61.1.1.3.4",
            "id-camellia256-wrap",
        ),
    ],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    plain_key,
    no_key_pair,
);
