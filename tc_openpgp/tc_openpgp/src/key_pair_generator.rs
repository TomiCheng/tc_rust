use std::sync::Arc;

use tc_algo::{AlgoError, Params};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::{DefaultPgpOperatorContext, PgpPrivateKey, PgpPublicKey};

/// Generates a pair of OpenPGP keys using the selected algorithm.
pub trait PgpKeyPairGenerator {
    /// Returns the public key followed by the private key.
    fn generate(&mut self, params: &dyn Params)
    -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError>;
}

/// Looks up registered generators by their OpenPGP algorithm tag.
pub trait PgpKeyPairGeneratorProvider: Send + Sync {
    fn get_by_algorithm(
        &self,
        tag: PublicKeyAlgorithmTag,
    ) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError>;
}

pub(crate) type GeneratorFactory =
    Arc<dyn Fn(&DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator> + Send + Sync>;
