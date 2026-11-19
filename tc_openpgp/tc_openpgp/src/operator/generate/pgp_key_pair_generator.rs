use tc_algo::{AlgoError, Params};

use crate::{PgpPrivateKey, PgpPublicKey};

/// Generates a pair of OpenPGP keys using the selected algorithm.
pub trait PgpKeyPairGenerator {
    /// Returns the public key followed by the private key.
    fn generate(&mut self, params: &dyn Params)
    -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError>;
}
