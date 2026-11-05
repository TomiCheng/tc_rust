use std::sync::Arc;
use crate::digest::{DefaultDigestProvider, DigestEntry, DigestProvider};

use crate::{Algo, CipherEntry, Policy};

pub(crate) struct DefaultAlgo {
    digest: DefaultDigestProvider,
    #[allow(dead_code, reason = "nothing reads it yet")]
    ciphers: Vec<Box<dyn CipherEntry>>,
}

impl DefaultAlgo {
    pub(crate) fn new(
        digests: Vec<Box<dyn DigestEntry>>,
        ciphers: Vec<Box<dyn CipherEntry>>,
        policy: Option<Arc<dyn Policy>>,
    ) -> Self {
        Self {
            digest: DefaultDigestProvider::new(digests, policy),
            ciphers,
        }
    }
}

impl Algo for DefaultAlgo {
    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }
}
