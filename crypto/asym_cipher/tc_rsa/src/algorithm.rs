//! The name of the algorithm.

/// The name every RSA engine of the crate writes through `Display`, as
/// Bouncy Castle's `AlgorithmName` is: `"RSA"`. An encoding over an engine
/// builds its own name on it, as `RSA/PKCS1Padding`.
pub const ALGO_NAME: &str = "RSA";

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::string::ToString;

    use super::ALGO_NAME;
    use crate::{FixedRsaCoreEngine, FixedRsaCrtCoreEngine, RsaBlindedEngine};

    #[test]
    fn every_engine_is_named_rsa() {
        assert_eq!(FixedRsaCoreEngine::<1>::new().to_string(), ALGO_NAME);
        assert_eq!(FixedRsaCrtCoreEngine::<1, 1>::new().to_string(), ALGO_NAME);
        let blinded = RsaBlindedEngine::<FixedRsaCrtCoreEngine<1, 1>, _>::new(());
        assert_eq!(blinded.to_string(), ALGO_NAME);
        #[cfg(feature = "alloc")]
        {
            assert_eq!(crate::PaddedRsaCoreEngine::new().to_string(), ALGO_NAME);
            assert_eq!(crate::PaddedRsaCrtCoreEngine::new().to_string(), ALGO_NAME);
        }
        #[cfg(feature = "rustcrypto")]
        {
            assert_eq!(crate::RsaCoreEngineRustCrypto::new().to_string(), ALGO_NAME);
            assert_eq!(
                crate::RsaCrtCoreEngineRustCrypto::new().to_string(),
                ALGO_NAME
            );
        }
    }
}
