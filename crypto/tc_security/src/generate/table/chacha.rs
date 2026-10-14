use tc_asn1::NamedOid;

use super::{no_key_pair, plain_key};
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

fn check_chacha(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 128 | 256,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

fn check_256(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 256 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

pub(super) const CHACHA: GeneratorEntry = GeneratorEntry::new(
    &["CHACHA"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_chacha,
    plain_key,
    no_key_pair,
);

pub(super) const CHACHA7539: GeneratorEntry = GeneratorEntry::new(
    &["CHACHA7539", "CHACHA20", "CHACHA20-POLY1305"],
    &[NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x12,
        ],
        "1.2.840.113549.1.9.16.3.18",
        "id-alg-AEADChaCha20Poly1305",
    )],
    KeyGenParams::Basic { strength: 256 },
    check_256,
    plain_key,
    no_key_pair,
);

pub(super) const XCHACHA20: GeneratorEntry = GeneratorEntry::new(
    &["XCHACHA20", "XCHACHA20-POLY1305"],
    &[],
    KeyGenParams::Basic { strength: 256 },
    check_256,
    plain_key,
    no_key_pair,
);
