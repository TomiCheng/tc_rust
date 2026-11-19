use tc_algo::{AlgoError, ErrorKind, Params};

use crate::{PgpPrivateKey, PgpPublicKey};

/// Generates a pair of OpenPGP keys using the selected algorithm.
pub trait PgpKeyPairGenerator {
    /// Returns the public key followed by the private key.
    fn generate(&mut self, params: &dyn Params)
    -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError>;

    /// Generates keys for an algorithm with fixed parameters.
    fn generate_without_params(&mut self) -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidKeyGenParams))
    }
}
