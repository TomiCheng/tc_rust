//! Salsa20、RC4、VMPC 與 HC 的金鑰產生器：預設長度同 BC 的 `GeneratorUtilities`，HC-256 是 256 bits，
//! 其餘 128 bits。

#[cfg(feature = "rc4")]
use tc_asn1::NamedOid;

use super::{no_key_pair, plain_key};
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

#[cfg(any(feature = "salsa20", feature = "hc"))]
fn check_128_or_256(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 128 | 256,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "salsa20")]
pub(super) const SALSA20: GeneratorEntry = GeneratorEntry::new(
    &["SALSA20"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_128_or_256,
    plain_key,
    no_key_pair,
);

/// RC4 的金鑰 1 到 256 bytes。
#[cfg(feature = "rc4")]
fn check_rc4(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 1..=2048 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "rc4")]
pub(super) const RC4: GeneratorEntry = GeneratorEntry::new(
    &["RC4", "ARC4", "ARCFOUR"],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x04],
        "1.2.840.113549.3.4",
        "rc4",
    )],
    KeyGenParams::Basic { strength: 128 },
    check_rc4,
    plain_key,
    no_key_pair,
);

/// VMPC 的金鑰 16 到 64 bytes。
#[cfg(feature = "vmpc")]
fn check_vmpc(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 121..=512,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "vmpc")]
pub(super) const VMPC: GeneratorEntry = GeneratorEntry::new(
    &["VMPC"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_vmpc,
    plain_key,
    no_key_pair,
);

#[cfg(feature = "vmpc")]
pub(super) const VMPC_KSA3: GeneratorEntry = GeneratorEntry::new(
    &["VMPC-KSA3", "VMPC_KSA3"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_vmpc,
    plain_key,
    no_key_pair,
);

#[cfg(feature = "hc")]
fn check_128(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 128 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

#[cfg(feature = "hc")]
pub(super) const HC128: GeneratorEntry = GeneratorEntry::new(
    &["HC128"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_128,
    plain_key,
    no_key_pair,
);

#[cfg(feature = "hc")]
pub(super) const HC256: GeneratorEntry = GeneratorEntry::new(
    &["HC256"],
    &[],
    KeyGenParams::Basic { strength: 256 },
    check_128_or_256,
    plain_key,
    no_key_pair,
);
