use rand::CryptoRng;
use tc_rc_cipher::{RC5_MAX_KEY_BYTES, RC5_MAX_ROUNDS};

use super::random_key;
use crate::SecurityError;
use crate::generate::generator_entry::Generate;
use crate::generate::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;

const MAX_STRENGTH: usize = RC5_MAX_KEY_BYTES * 8;

fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    match params {
        KeyGenParams::Basic {
            strength: 1..=MAX_STRENGTH,
        }
        | KeyGenParams::Rc5 {
            strength: 1..=MAX_STRENGTH,
            rounds: 0..=RC5_MAX_ROUNDS,
        } => Ok(()),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

fn generate_key(params: &KeyGenParams, rng: &mut dyn CryptoRng) -> AnyParams {
    match *params {
        KeyGenParams::Rc5 { strength, rounds } => AnyParams::rc5(random_key(strength, rng), rounds),
        _ => AnyParams::new(random_key(params.strength(), rng)),
    }
}

pub(super) const RC5: GeneratorEntry = GeneratorEntry::new(
    &["RC5", "RC5-32"],
    &[],
    KeyGenParams::Basic { strength: 128 },
    check_params,
    Generate::Key(generate_key),
);

pub(super) const RC5_64: GeneratorEntry = GeneratorEntry::new(
    &["RC5-64"],
    &[],
    KeyGenParams::Basic { strength: 256 },
    check_params,
    Generate::Key(generate_key),
);
