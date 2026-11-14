use tc_asym_cipher::KeyPairGeneratorInit;

use crate::{AlgoError, Params};

// Named, so that the public key and the private key cannot be swapped by their order
pub struct KeyPair {
    public: Box<dyn Params>,
    private: Box<dyn Params>,
}

impl KeyPair {
    pub fn new(public: Box<dyn Params>, private: Box<dyn Params>) -> Self {
        Self { public, private }
    }

    pub fn public(&self) -> &dyn Params {
        self.public.as_ref()
    }

    pub fn private(&self) -> &dyn Params {
        self.private.as_ref()
    }

    // The two keys to own apart, public first: (public, private)
    pub fn into_parts(self) -> (Box<dyn Params>, Box<dyn Params>) {
        (self.public, self.private)
    }
}

// A KeyPairGenerator of tc_asym_cipher whose keys are any params, with AlgoError for its errors and
// an init taking any params, so that every row fits behind Box<dyn KeyPairGenerator> and still goes
// wherever a tc_asym_cipher KeyPairGenerator does
pub trait KeyPairGenerator:
    tc_asym_cipher::KeyPairGenerator<
        PublicKey = Box<dyn Params>,
        PrivateKey = Box<dyn Params>,
        Error = AlgoError,
    > + KeyPairGeneratorInit<dyn Params, Error = AlgoError>
{
    // generate_key_pair as a KeyPair, whose two keys are named
    fn generate(&mut self) -> Result<KeyPair, AlgoError> {
        let (public, private) = self.generate_key_pair()?;
        Ok(KeyPair::new(public, private))
    }
}
