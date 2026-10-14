use super::{no_key_pair, plain_key};
use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

fn check_128(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 128 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

fn check_160(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 160 } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

pub(super) const ASCON_AEAD128: GeneratorEntry = GeneratorEntry::new(
    &["ASCON-AEAD128"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_128,
    plain_key,
    no_key_pair,
);

pub(super) const ASCON128: GeneratorEntry = GeneratorEntry::new(
    &["ASCON-128"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_128,
    plain_key,
    no_key_pair,
);

pub(super) const ASCON128A: GeneratorEntry = GeneratorEntry::new(
    &["ASCON-128A"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_128,
    plain_key,
    no_key_pair,
);

pub(super) const ASCON80PQ: GeneratorEntry = GeneratorEntry::new(
    &["ASCON-80PQ"],
    &[],
    KeyGenParams::Basic { strength: 160 },
    check_160,
    plain_key,
    no_key_pair,
);
