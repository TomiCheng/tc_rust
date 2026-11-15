#[cfg(feature = "ascon-aead128")]
use tc_ascon_aead::AsconAead128Engine;
#[cfg(any(feature = "ascon128", feature = "ascon128a", feature = "ascon80pq"))]
use tc_ascon_aead::{AsconLegacyEngine, AsconLegacyVariant};

use super::aead_engine::{AeadEngine, row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// Ascon-AEAD128 of NIST SP 800-232. Bouncy Castle's CipherUtilities has no Ascon, so the name is
// the standard's
#[cfg(feature = "ascon-aead128")]
pub(super) fn ascon_aead128(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("ASCON-AEAD128", &[], || {
        Box::new(AeadEngine(AsconAead128Engine::new()))
    })]
}

// The variants of Ascon v1.2 that SP 800-232 supersedes, for data made before it
#[cfg(feature = "ascon128")]
pub(super) fn ascon128(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("ASCON-128", &[], || {
        Box::new(AeadEngine(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon128,
        )))
    })]
}

#[cfg(feature = "ascon128a")]
pub(super) fn ascon128a(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("ASCON-128A", &[], || {
        Box::new(AeadEngine(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon128a,
        )))
    })]
}

#[cfg(feature = "ascon80pq")]
pub(super) fn ascon80pq(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("ASCON-80PQ", &[], || {
        Box::new(AeadEngine(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon80pq,
        )))
    })]
}

#[cfg(test)]
mod tests {
    // The first known answer of the official ascon-c KATs, as tc_ascon_aead tests it
    #[cfg(feature = "ascon-aead128")]
    #[test]
    fn ascon_aead128_gives_the_first_known_answer_of_ascon_c() {
        super::super::aead_engine::assert_empty_vector(
            "ASCON-AEAD128",
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "4f9c278211bec9316bf68f46ee8b2ec6",
        );
    }

    // The legacy variants decrypt what they encrypt, and are not the standard
    #[cfg(all(
        feature = "ascon-aead128",
        feature = "ascon128",
        feature = "ascon128a",
        feature = "ascon80pq"
    ))]
    #[test]
    fn the_legacy_variants_decrypt_back_and_differ_from_the_standard() {
        use crate::params::AeadParamsOwned;
        use crate::{AlgoBuilder, DefaultAlgoBuilder};

        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let seal = |name: &str, key: Vec<u8>| {
            let params = AeadParamsOwned::new(key, vec![0x24; 16], 16, b"aad".to_vec());
            let sealed = ciphers.encrypt_by_name(name, &params, b"message").unwrap();
            let opened = ciphers.decrypt_by_name(name, &params, &sealed).unwrap();
            assert_eq!(opened, b"message", "{name}");
            sealed
        };
        let standard = seal("ASCON-AEAD128", vec![0x42; 16]);
        assert_ne!(seal("ASCON-128", vec![0x42; 16]), standard);
        assert_ne!(seal("ASCON-128A", vec![0x42; 16]), standard);
        seal("ASCON-80PQ", vec![0x42; 20]);
    }
}
