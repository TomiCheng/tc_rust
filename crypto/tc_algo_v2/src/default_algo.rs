use std::sync::Arc;
use crate::cipher::{CipherEntry, CipherProvider};
use crate::default_provider::DefaultProvider;
use crate::digest::{DigestEntry, DigestProvider};
use crate::mac::{MacEntry, MacProvider};
use crate::wrap::{WrapperEntry, WrapperProvider};
use crate::xof::{XofEntry, XofProvider};

use crate::{
    Algo, KeyGeneratorEntry, KeyGeneratorProvider, KeyPairGeneratorEntry, KeyPairGeneratorProvider,
    Policy,
};

pub(crate) struct DefaultAlgo {
    digest: DefaultProvider<dyn DigestEntry>,
    xof: DefaultProvider<dyn XofEntry>,
    cipher: DefaultProvider<dyn CipherEntry>,
    mac: DefaultProvider<dyn MacEntry>,
    wrap: DefaultProvider<dyn WrapperEntry>,
    key_generator: DefaultProvider<dyn KeyGeneratorEntry>,
    key_pair_generator: DefaultProvider<dyn KeyPairGeneratorEntry>,
}

impl DefaultAlgo {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        digests: Vec<Box<dyn DigestEntry>>,
        xofs: Vec<Box<dyn XofEntry>>,
        ciphers: Vec<Box<dyn CipherEntry>>,
        macs: Vec<Box<dyn MacEntry>>,
        wrappers: Vec<Box<dyn WrapperEntry>>,
        key_generators: Vec<Box<dyn KeyGeneratorEntry>>,
        key_pair_generators: Vec<Box<dyn KeyPairGeneratorEntry>>,
        policy: Option<Arc<dyn Policy>>,
    ) -> Self {
        Self {
            digest: DefaultProvider::new(digests, policy.clone()),
            xof: DefaultProvider::new(xofs, policy.clone()),
            cipher: DefaultProvider::new(ciphers, policy.clone()),
            mac: DefaultProvider::new(macs, policy.clone()),
            wrap: DefaultProvider::new(wrappers, policy.clone()),
            key_generator: DefaultProvider::new(key_generators, policy.clone()),
            key_pair_generator: DefaultProvider::new(key_pair_generators, policy),
        }
    }
}

impl Algo for DefaultAlgo {
    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }

    fn xof(&self) -> &dyn XofProvider {
        &self.xof
    }

    fn cipher(&self) -> &dyn CipherProvider {
        &self.cipher
    }

    fn mac(&self) -> &dyn MacProvider {
        &self.mac
    }

    fn wrap(&self) -> &dyn WrapperProvider {
        &self.wrap
    }

    fn key_generator(&self) -> &dyn KeyGeneratorProvider {
        &self.key_generator
    }

    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider {
        &self.key_pair_generator
    }
}
