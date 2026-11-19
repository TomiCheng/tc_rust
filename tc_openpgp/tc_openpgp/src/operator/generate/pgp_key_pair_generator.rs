use tc_algo::{AlgoError, Params};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

use crate::{PgpKeyPair, PgpPrivateKey, PgpPublicKey};

/// Generates OpenPGP keys using the current algorithm parameters.
pub trait PgpKeyPairGenerator:
    KeyPairGenerator<PublicKey = PgpPublicKey, PrivateKey = PgpPrivateKey, Error = AlgoError>
    + KeyPairGeneratorInit<dyn Params, Error = AlgoError>
{
    fn generate(&mut self) -> Result<PgpKeyPair, AlgoError> {
        let (public, private) = self.generate_key_pair()?;
        Ok(PgpKeyPair::new(public, private))
    }
}
