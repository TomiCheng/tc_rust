use core::fmt;
use std::sync::Arc;

use crate::cipher::CipherEntry;
use crate::default_algo::DefaultAlgo;
use crate::digest::{self, DigestEntry};
use crate::{Algo, AlgoBuilder, Policy};

#[derive(Clone)]
pub struct DefaultAlgoBuilder {
    digests: Vec<fn() -> Box<dyn DigestEntry>>,
    ciphers: Vec<fn() -> Box<dyn CipherEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

// Starts with the algorithms whose features are on
impl Default for DefaultAlgoBuilder {
    fn default() -> Self {
        Self {
            digests: digest::BUILT_IN.to_vec(),
            ciphers: Vec::new(),
            policy: None,
        }
    }
}

impl DefaultAlgoBuilder {
    pub fn reg_digest(&mut self, create: fn() -> Box<dyn DigestEntry>) {
        self.digests.push(create);
    }

    pub fn reg_cipher(&mut self, create: fn() -> Box<dyn CipherEntry>) {
        self.ciphers.push(create);
    }

    pub fn set_policy(&mut self, policy: impl Policy + 'static) {
        self.policy = Some(Arc::new(policy));
    }

    pub fn clear_policy(&mut self) {
        self.policy = None;
    }
}

// The last registered comes first, so that it is the one a lookup by its name finds
impl DefaultAlgoBuilder {
    fn digest_rows(&self) -> Vec<Box<dyn DigestEntry>> {
        self.digests.iter().rev().map(|create| create()).collect()
    }

    fn cipher_rows(&self) -> Vec<Box<dyn CipherEntry>> {
        self.ciphers.iter().rev().map(|create| create()).collect()
    }
}

impl AlgoBuilder for DefaultAlgoBuilder {
    fn build(&self) -> Box<dyn Algo> {
        Box::new(DefaultAlgo::new(
            self.digest_rows(),
            self.cipher_rows(),
            self.policy.clone(),
        ))
    }
}

// A policy need not be Debug, so this shows only that there is one
impl fmt::Debug for DefaultAlgoBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultAlgoBuilder")
            .field("digests", &self.digests.len())
            .field("ciphers", &self.ciphers.len())
            .field("policy", &self.policy.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::DefaultAlgoBuilder;
    use crate::EntryBase;
    use crate::digest::{Digest, DigestEntry};

    struct Row(&'static str);

    impl EntryBase for Row {
        fn name(&self) -> &str {
            self.0
        }
    }

    impl DigestEntry for Row {
        fn create(&self) -> Box<dyn Digest> {
            unreachable!("these tests only read the names")
        }
    }

    fn first() -> Box<dyn DigestEntry> {
        Box::new(Row("FIRST"))
    }

    fn second() -> Box<dyn DigestEntry> {
        Box::new(Row("SECOND"))
    }

    #[test]
    fn the_last_registered_digest_comes_first_and_the_built_in_ones_last() {
        let mut builder = DefaultAlgoBuilder::default();
        let built_in = builder.digests.len();
        builder.reg_digest(first);
        builder.reg_digest(second);

        let rows = builder.digest_rows();
        assert_eq!(rows.len(), built_in + 2);
        assert_eq!(rows[0].name(), "SECOND");
        assert_eq!(rows[1].name(), "FIRST");
    }

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
