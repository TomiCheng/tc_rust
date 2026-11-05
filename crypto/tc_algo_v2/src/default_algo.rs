use std::sync::Arc;
use crate::digest::{DefaultDigestProvider, DigestEntry, DigestProvider};

use crate::{Algo, Policy};

pub(crate) struct DefaultAlgo {
    digest: DefaultDigestProvider,
    #[allow(dead_code, reason = "nothing reads it yet")]
    policy: Option<Arc<dyn Policy>>,
}

impl DefaultAlgo {
    pub(crate) fn new(digests: Vec<Box<dyn DigestEntry>>, policy: Option<Arc<dyn Policy>>) -> Self {
        Self {
            digest: DefaultDigestProvider::new(digests),
            policy,
        }
    }
}

impl Algo for DefaultAlgo {
    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }
}
