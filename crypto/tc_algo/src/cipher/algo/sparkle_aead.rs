use tc_sparkle_aead::{SparkleEngine, SparkleVariant};

use super::aead_engine::{AeadEngine, row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// Schwaemm, the AEAD of the Sparkle family, a finalist of NIST's lightweight cryptography, named
// after its rate and capacity in bits: SCHWAEMM256-128 is the primary member. Bouncy Castle's
// CipherUtilities has no Sparkle, so the names are the designers'
#[cfg(feature = "schwaemm128-128")]
pub(super) fn schwaemm128_128(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("SCHWAEMM128-128", &[], || {
        Box::new(AeadEngine(SparkleEngine::new(
            SparkleVariant::Schwaemm128_128,
        )))
    })]
}

#[cfg(feature = "schwaemm256-128")]
pub(super) fn schwaemm256_128(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("SCHWAEMM256-128", &[], || {
        Box::new(AeadEngine(SparkleEngine::new(
            SparkleVariant::Schwaemm256_128,
        )))
    })]
}

#[cfg(feature = "schwaemm192-192")]
pub(super) fn schwaemm192_192(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("SCHWAEMM192-192", &[], || {
        Box::new(AeadEngine(SparkleEngine::new(
            SparkleVariant::Schwaemm192_192,
        )))
    })]
}

#[cfg(feature = "schwaemm256-256")]
pub(super) fn schwaemm256_256(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("SCHWAEMM256-256", &[], || {
        Box::new(AeadEngine(SparkleEngine::new(
            SparkleVariant::Schwaemm256_256,
        )))
    })]
}

#[cfg(test)]
mod tests {
    // The first known answer of Schwaemm128-128 in tc_sparkle_aead's tests
    #[cfg(feature = "schwaemm128-128")]
    #[test]
    fn schwaemm128_128_gives_its_first_known_answer() {
        super::super::aead_engine::assert_empty_vector(
            "SCHWAEMM128-128",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "ddce77cdb748e6d053cab7e9190a8349",
        );
    }

    // Each member takes a key and a tag of its capacity and a nonce of its rate
    #[cfg(all(
        feature = "schwaemm256-128",
        feature = "schwaemm192-192",
        feature = "schwaemm256-256"
    ))]
    #[test]
    fn each_member_takes_its_sizes_and_decrypts_back() {
        use crate::params::AeadParamsOwned;
        use crate::{AlgoBuilder, DefaultAlgoBuilder};

        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for (name, key, nonce) in [
            ("SCHWAEMM256-128", 16, 32),
            ("SCHWAEMM192-192", 24, 24),
            ("SCHWAEMM256-256", 32, 32),
        ] {
            let params =
                AeadParamsOwned::new(vec![0x42; key], vec![0x24; nonce], key, b"aad".to_vec());
            let sealed = ciphers.encrypt_by_name(name, &params, b"message").unwrap();
            assert_eq!(sealed.len(), 7 + key, "{name}");
            let opened = ciphers.decrypt_by_name(name, &params, &sealed).unwrap();
            assert_eq!(opened, b"message", "{name}");
        }
    }
}
