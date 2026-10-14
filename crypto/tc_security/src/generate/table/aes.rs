use tc_asn1::NamedOid;

use super::{no_key_pair, plain_key};
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

// NIST 的 AES OID 都在 2.16.840.1.101.3.4.1 底下，只差最後一個 arc
macro_rules! nist_aes {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 128 | 192 | 256,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

/// 沒寫長度時產生 192 bits，同 BC；BC 的 `AESWRAP` 也對到這一列。
pub(super) const AES: GeneratorEntry = GeneratorEntry::new(
    &["AES", "AESWRAP"],
    &[],
    KeyGenParams::Basic { strength: 192 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 128 bits。OID 照 BC：這個長度的各個模式與 key wrap 都對到這一列。
pub(super) const AES128: GeneratorEntry = GeneratorEntry::new(
    &["AES128"],
    &[
        nist_aes!(0x01, "2.16.840.1.101.3.4.1.1", "id-aes128-ECB"),
        nist_aes!(0x02, "2.16.840.1.101.3.4.1.2", "id-aes128-CBC"),
        nist_aes!(0x03, "2.16.840.1.101.3.4.1.3", "id-aes128-OFB"),
        nist_aes!(0x04, "2.16.840.1.101.3.4.1.4", "id-aes128-CFB"),
        nist_aes!(0x05, "2.16.840.1.101.3.4.1.5", "id-aes128-wrap"),
        nist_aes!(0x06, "2.16.840.1.101.3.4.1.6", "id-aes128-GCM"),
        nist_aes!(0x07, "2.16.840.1.101.3.4.1.7", "id-aes128-CCM"),
        nist_aes!(0x08, "2.16.840.1.101.3.4.1.8", "id-aes128-wrap-pad"),
    ],
    KeyGenParams::Basic { strength: 128 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 192 bits。
pub(super) const AES192: GeneratorEntry = GeneratorEntry::new(
    &["AES192"],
    &[
        nist_aes!(0x15, "2.16.840.1.101.3.4.1.21", "id-aes192-ECB"),
        nist_aes!(0x16, "2.16.840.1.101.3.4.1.22", "id-aes192-CBC"),
        nist_aes!(0x17, "2.16.840.1.101.3.4.1.23", "id-aes192-OFB"),
        nist_aes!(0x18, "2.16.840.1.101.3.4.1.24", "id-aes192-CFB"),
        nist_aes!(0x19, "2.16.840.1.101.3.4.1.25", "id-aes192-wrap"),
        nist_aes!(0x1a, "2.16.840.1.101.3.4.1.26", "id-aes192-GCM"),
        nist_aes!(0x1b, "2.16.840.1.101.3.4.1.27", "id-aes192-CCM"),
        nist_aes!(0x1c, "2.16.840.1.101.3.4.1.28", "id-aes192-wrap-pad"),
    ],
    KeyGenParams::Basic { strength: 192 },
    check_params,
    plain_key,
    no_key_pair,
);

/// 256 bits。
pub(super) const AES256: GeneratorEntry = GeneratorEntry::new(
    &["AES256"],
    &[
        nist_aes!(0x29, "2.16.840.1.101.3.4.1.41", "id-aes256-ECB"),
        nist_aes!(0x2a, "2.16.840.1.101.3.4.1.42", "id-aes256-CBC"),
        nist_aes!(0x2b, "2.16.840.1.101.3.4.1.43", "id-aes256-OFB"),
        nist_aes!(0x2c, "2.16.840.1.101.3.4.1.44", "id-aes256-CFB"),
        nist_aes!(0x2d, "2.16.840.1.101.3.4.1.45", "id-aes256-wrap"),
        nist_aes!(0x2e, "2.16.840.1.101.3.4.1.46", "id-aes256-GCM"),
        nist_aes!(0x2f, "2.16.840.1.101.3.4.1.47", "id-aes256-CCM"),
        nist_aes!(0x30, "2.16.840.1.101.3.4.1.48", "id-aes256-wrap-pad"),
    ],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    plain_key,
    no_key_pair,
);
