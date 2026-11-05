use std::sync::Arc;
use crate::cipher::{CipherEntry, CipherProvider, DefaultCipherProvider};
use crate::digest::{DefaultDigestProvider, DigestEntry, DigestProvider};

use crate::{Algo, Policy};

pub(crate) struct DefaultAlgo {
    digest: DefaultDigestProvider,
    cipher: DefaultCipherProvider,
}

impl DefaultAlgo {
    pub(crate) fn new(
        digests: Vec<Box<dyn DigestEntry>>,
        ciphers: Vec<Box<dyn CipherEntry>>,
        policy: Option<Arc<dyn Policy>>,
    ) -> Self {
        Self {
            digest: DefaultDigestProvider::new(digests, policy.clone()),
            cipher: DefaultCipherProvider::new(ciphers, policy),
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
}
