use core::fmt;
use std::sync::Arc;

use crate::default_algo::DefaultAlgo;
use crate::digest::DigestEntry;
use crate::{Algo, AlgoBuilder, Policy};

#[derive(Clone, Default)]
pub struct DefaultAlgoBuilder {
    digests: Vec<fn() -> Box<dyn DigestEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

impl DefaultAlgoBuilder {
    pub fn reg_digest(&mut self, create: fn() -> Box<dyn DigestEntry>) {
        self.digests.push(create);
    }

    pub fn set_policy(&mut self, policy: impl Policy + 'static) {
        self.policy = Some(Arc::new(policy));
    }

    pub fn clear_policy(&mut self) {
        self.policy = None;
    }
}

impl AlgoBuilder for DefaultAlgoBuilder {
    fn build(&self) -> Box<dyn Algo> {
        let digests = self.digests.iter().map(|create| create()).collect();
        Box::new(DefaultAlgo::new(digests, self.policy.clone()))
    }
}

// A policy need not be Debug, so this shows only that there is one
impl fmt::Debug for DefaultAlgoBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultAlgoBuilder")
            .field("digests", &self.digests.len())
            .field("policy", &self.policy.is_some())
            .finish()
    }
}
