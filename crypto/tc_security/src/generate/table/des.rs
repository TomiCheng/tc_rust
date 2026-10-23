//! DES 與 Triple DES 的金鑰：同 BC 的 `DesKeyGenerator`、`DesEdeKeyGenerator`，
//! 取亂數、設 odd parity，弱金鑰或分段重複（退化成單 DES）就重抽。

use rand::CryptoRng;
use tc_asn1::NamedOid;
#[cfg(feature = "des")]
use tc_des::is_weak_key;
use tc_des::set_odd_parity;
#[cfg(feature = "desede")]
use tc_des::{EDE2_KEY_BYTES, EDE3_KEY_BYTES, is_real_ede_key, is_weak_ede_key};

use super::no_key_pair;
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;

/// 取亂數並設 odd parity，直到 `usable` 接受為止。
fn draw_key(len: usize, rng: &mut dyn CryptoRng, usable: fn(&[u8]) -> bool) -> Vec<u8> {
    let mut key = vec![0; len];
    loop {
        rng.fill_bytes(&mut key);
        set_odd_parity(&mut key);
        if usable(&key) {
            return key;
        }
    }
}

/// 同 BC 接受 56 或 64 bits（不算或算進 parity bit），都產生 8 bytes。
#[cfg(feature = "des")]
fn check_des_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 56 | 64 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "des")]
fn generate_des_key(_: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<AnyParams, SecurityError> {
    let key = draw_key(8, rng, |key| {
        key.first_chunk().is_some_and(|key| !is_weak_key(key))
    });
    Ok(AnyParams::new(key))
}

/// 同 BC：112 或 128 bits 是兩把金鑰（16 bytes），168 或 192 bits 是三把（24 bytes）。
#[cfg(feature = "desede")]
fn check_desede_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 112 | 128 | 168 | 192,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "desede")]
fn generate_desede_key(
    params: &KeyGenParams,
    rng: &mut dyn CryptoRng,
) -> Result<AnyParams, SecurityError> {
    let len = match params {
        KeyGenParams::Basic {
            strength: 112 | 128,
        } => EDE2_KEY_BYTES,
        _ => EDE3_KEY_BYTES,
    };
    let key = draw_key(len, rng, |key| {
        !is_weak_ede_key(key) && is_real_ede_key(key)
    });
    Ok(AnyParams::new(key))
}

/// 預設 64 bits，同 BC。OID 照 BC 是 OIW 的四個模式。
#[cfg(feature = "des")]
pub(super) const DES: GeneratorEntry = GeneratorEntry::new(
    &["DES"],
    &[
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x07], "1.3.14.3.2.7", "desCBC"),
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x09], "1.3.14.3.2.9", "desCFB"),
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x06], "1.3.14.3.2.6", "desECB"),
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x08], "1.3.14.3.2.8", "desOFB"),
    ],
    KeyGenParams::Basic { strength: 64 },
    check_des_params,
    generate_des_key,
    no_key_pair,
);

/// 預設 128 bits（兩把金鑰），同 BC。
#[cfg(feature = "desede")]
pub(super) const DESEDE: GeneratorEntry = GeneratorEntry::new(
    &["DESEDE", "DESEDEWRAP", "TDEA"],
    &[NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x11],
        "1.3.14.3.2.17",
        "desEDE",
    )],
    KeyGenParams::Basic { strength: 128 },
    check_desede_params,
    generate_desede_key,
    no_key_pair,
);

/// 預設 192 bits（三把金鑰），同 BC。
#[cfg(feature = "desede")]
pub(super) const DESEDE3: GeneratorEntry = GeneratorEntry::new(
    &["DESEDE3"],
    &[
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
            "1.2.840.113549.3.7",
            "des-ede3-cbc",
        ),
        NamedOid::new(
            &[
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x06,
            ],
            "1.2.840.113549.1.9.16.3.6",
            "id-alg-CMS3DESwrap",
        ),
    ],
    KeyGenParams::Basic { strength: 192 },
    check_desede_params,
    generate_desede_key,
    no_key_pair,
);
