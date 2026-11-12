use tc_buffered_cipher::BufferedAeadCipher;
use tc_sparkle_aead::{SparkleEngine, SparkleVariant};

use super::compose::boxed;
use super::specs::AeadSpec;
use crate::cipher::dyn_cipher::DynCipher;

fn schwaemm(variant: SparkleVariant) -> Box<dyn DynCipher> {
    boxed(BufferedAeadCipher::new(SparkleEngine::new(variant)))
}

// SCHWAEMMr-c has an r-bit nonce and a c-bit key and tag
pub(super) const SCHWAEMM128_128: AeadSpec = AeadSpec {
    names: &["SCHWAEMM128-128"],
    create: || schwaemm(SparkleVariant::Schwaemm128_128),
    oids: &[],
};

pub(super) const SCHWAEMM256_128: AeadSpec = AeadSpec {
    names: &["SCHWAEMM256-128"],
    create: || schwaemm(SparkleVariant::Schwaemm256_128),
    oids: &[],
};

pub(super) const SCHWAEMM192_192: AeadSpec = AeadSpec {
    names: &["SCHWAEMM192-192"],
    create: || schwaemm(SparkleVariant::Schwaemm192_192),
    oids: &[],
};

pub(super) const SCHWAEMM256_256: AeadSpec = AeadSpec {
    names: &["SCHWAEMM256-256"],
    create: || schwaemm(SparkleVariant::Schwaemm256_256),
    oids: &[],
};
