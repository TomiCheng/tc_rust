use core::fmt;
use std::sync::Arc;

use crate::default_algo::DefaultAlgo;
use crate::digest::{self, DigestEntry};
use crate::{Algo, AlgoBuilder, Policy};

#[derive(Clone)]
pub struct DefaultAlgoBuilder {
    digests: Vec<fn() -> Box<dyn DigestEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

// Starts with the algorithms whose features are on
impl Default for DefaultAlgoBuilder {
    fn default() -> Self {
        Self {
            digests: digest::BUILT_IN.to_vec(),
            policy: None,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::DefaultAlgoBuilder;

    #[cfg(feature = "sha256")]
    #[test]
    fn a_new_builder_has_sha256_when_its_feature_is_on() {
        let builder = DefaultAlgoBuilder::default();
        let names: Vec<String> = builder
            .digests
            .iter()
            .map(|create| create().name().to_string())
            .collect();
        assert!(names.iter().any(|name| name == "SHA-256"));
    }

    #[cfg(not(feature = "sha256"))]
    #[test]
    fn a_new_builder_has_no_digest_when_no_feature_is_on() {
        assert!(DefaultAlgoBuilder::default().digests.is_empty());
    }
}
