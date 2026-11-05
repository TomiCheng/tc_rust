use std::sync::Arc;

use crate::{Algo, DigestEntry, Policy};

#[allow(dead_code, reason = "nothing reads them yet")]
pub(crate) struct DefaultAlgo {
    digests: Vec<Box<dyn DigestEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

impl DefaultAlgo {
    pub(crate) fn new(digests: Vec<Box<dyn DigestEntry>>, policy: Option<Arc<dyn Policy>>) -> Self {
        Self { digests, policy }
    }
}

impl Algo for DefaultAlgo {}
