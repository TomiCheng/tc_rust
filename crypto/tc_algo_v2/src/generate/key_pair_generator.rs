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
}

pub trait KeyPairGenerator {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    fn generate(&mut self) -> Result<KeyPair, AlgoError>;
}
