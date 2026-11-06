use std::sync::Arc;
use crate::cipher::{CipherEntry, CipherProvider, DefaultCipherProvider};
use crate::digest::{DefaultDigestProvider, DigestEntry, DigestProvider};
use crate::generate::DefaultKeyGeneratorProvider;
use crate::mac::{DefaultMacProvider, MacEntry, MacProvider};

use crate::{Algo, KeyGeneratorEntry, KeyGeneratorProvider, Policy};

pub(crate) struct DefaultAlgo {
    digest: DefaultDigestProvider,
    cipher: DefaultCipherProvider,
    mac: DefaultMacProvider,
    key_generator: DefaultKeyGeneratorProvider,
}

impl DefaultAlgo {
    pub(crate) fn new(
        digests: Vec<Box<dyn DigestEntry>>,
        ciphers: Vec<Box<dyn CipherEntry>>,
        macs: Vec<Box<dyn MacEntry>>,
        key_generators: Vec<Box<dyn KeyGeneratorEntry>>,
        policy: Option<Arc<dyn Policy>>,
    ) -> Self {
        Self {
            digest: DefaultDigestProvider::new(digests, policy.clone()),
            cipher: DefaultCipherProvider::new(ciphers, policy.clone()),
            mac: DefaultMacProvider::new(macs, policy.clone()),
            key_generator: DefaultKeyGeneratorProvider::new(key_generators, policy),
        }
    }
}

impl Algo for DefaultAlgo {
    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }

    fn cipher(&self) -> &dyn CipherProvider {
        &self.cipher
    }

    fn mac(&self) -> &dyn MacProvider {
        &self.mac
    }

    fn key_generator(&self) -> &dyn KeyGeneratorProvider {
        &self.key_generator
    }
}
