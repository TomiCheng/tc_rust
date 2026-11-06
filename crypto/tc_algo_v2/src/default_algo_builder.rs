use core::fmt;
use std::sync::Arc;

use rand_core::CryptoRng;

use crate::cipher::{self, CipherEntry};
use crate::default_algo::DefaultAlgo;
use crate::default_algo_context::os_rand;
use crate::digest::{self, DigestEntry};
use crate::generate::{
    BUILT_IN_KEY_GENERATORS, BUILT_IN_KEY_PAIR_GENERATORS, CreateKeyGeneratorRows,
    CreateKeyPairGeneratorRows,
};
use crate::mac::{self, MacEntry};
use crate::wrap::{self, WrapperEntry};
use crate::xof::{self, XofEntry};
use crate::{
    Algo, AlgoBuilder, DefaultAlgoContext, KeyGeneratorEntry, KeyPairGeneratorEntry, Policy,
};

#[derive(Clone)]
pub struct DefaultAlgoBuilder {
    digests: Vec<digest::CreateRows>,
    xofs: Vec<xof::CreateRows>,
    ciphers: Vec<cipher::CreateRows>,
    macs: Vec<mac::CreateRows>,
    wrappers: Vec<wrap::CreateRows>,
    key_generators: Vec<CreateKeyGeneratorRows>,
    key_pair_generators: Vec<CreateKeyPairGeneratorRows>,
    policy: Option<Arc<dyn Policy>>,
    rand: fn() -> Box<dyn CryptoRng>,
}

// Starts with the algorithms whose features are on
impl Default for DefaultAlgoBuilder {
    fn default() -> Self {
        Self {
            digests: digest::BUILT_IN.to_vec(),
            xofs: xof::BUILT_IN.to_vec(),
            ciphers: cipher::BUILT_IN.to_vec(),
            macs: mac::BUILT_IN.to_vec(),
            wrappers: wrap::BUILT_IN.to_vec(),
            key_generators: BUILT_IN_KEY_GENERATORS.to_vec(),
            key_pair_generators: BUILT_IN_KEY_PAIR_GENERATORS.to_vec(),
            policy: None,
            rand: os_rand,
        }
    }
}

impl DefaultAlgoBuilder {
    pub fn reg_digest(&mut self, create: fn(&DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>>) {
        self.digests.push(create);
    }

    pub fn reg_xof(&mut self, create: fn(&DefaultAlgoContext) -> Vec<Box<dyn XofEntry>>) {
        self.xofs.push(create);
    }

    pub fn reg_cipher(&mut self, create: fn(&DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>) {
        self.ciphers.push(create);
    }

    pub fn reg_mac(&mut self, create: fn(&DefaultAlgoContext) -> Vec<Box<dyn MacEntry>>) {
        self.macs.push(create);
    }

    pub fn reg_wrap(&mut self, create: fn(&DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>>) {
        self.wrappers.push(create);
    }

    pub fn reg_key_generator(
        &mut self,
        create: fn(&DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>>,
    ) {
        self.key_generators.push(create);
    }

    pub fn reg_key_pair_generator(
        &mut self,
        create: fn(&DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>>,
    ) {
        self.key_pair_generators.push(create);
    }

    pub fn set_policy(&mut self, policy: impl Policy + 'static) {
        self.policy = Some(Arc::new(policy));
    }

    pub fn clear_policy(&mut self) {
        self.policy = None;
    }

    pub fn set_rand(&mut self, rand: fn() -> Box<dyn CryptoRng>) {
        self.rand = rand;
    }
}

// The last registered comes first, so that it is the one a lookup by its name finds. The rows of
// one function stay together, in the order it returns them
impl DefaultAlgoBuilder {
    fn digest_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
        self.digests
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn xof_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
        self.xofs
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn cipher_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
        self.ciphers
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn mac_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
        self.macs
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn wrapper_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>> {
        self.wrappers
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn key_generator_rows(&self, context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
        self.key_generators
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }

    fn key_pair_generator_rows(
        &self,
        context: &DefaultAlgoContext,
    ) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
        self.key_pair_generators
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect()
    }
}

impl AlgoBuilder for DefaultAlgoBuilder {
    fn build(&self) -> Box<dyn Algo> {
        let context = DefaultAlgoContext::new(self.rand);
        Box::new(DefaultAlgo::new(
            self.digest_rows(&context),
            self.xof_rows(&context),
            self.cipher_rows(&context),
            self.mac_rows(&context),
            self.wrapper_rows(&context),
            self.key_generator_rows(&context),
            self.key_pair_generator_rows(&context),
            self.policy.clone(),
        ))
    }
}

// A policy need not be Debug, so this shows only that there is one
impl fmt::Debug for DefaultAlgoBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultAlgoBuilder")
            .field("digests", &self.digests.len())
            .field("xofs", &self.xofs.len())
            .field("ciphers", &self.ciphers.len())
            .field("macs", &self.macs.len())
            .field("wrappers", &self.wrappers.len())
            .field("key_generators", &self.key_generators.len())
            .field("key_pair_generators", &self.key_pair_generators.len())
            .field("policy", &self.policy.is_some())
            .field("rand", &self.rand)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::DefaultAlgoBuilder;
    use crate::digest::{Digest, DigestEntry};
    use crate::{DefaultAlgoContext, EntryBase};

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

    fn first(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
        vec![Box::new(Row("FIRST"))]
    }

    fn second(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
        vec![Box::new(Row("SECOND"))]
    }

    #[test]
    fn the_last_registered_digest_comes_first_and_the_built_in_ones_last() {
        let context = DefaultAlgoContext::for_tests();
        let mut builder = DefaultAlgoBuilder::default();
        let built_in = builder.digest_rows(&context).len();
        builder.reg_digest(first);
        builder.reg_digest(second);

        let rows = builder.digest_rows(&context);
        assert_eq!(rows.len(), built_in + 2);
        assert_eq!(rows[0].name(), "SECOND");
        assert_eq!(rows[1].name(), "FIRST");
    }

    #[cfg(feature = "sha256")]
    #[test]
    fn a_new_builder_has_sha256_when_its_feature_is_on() {
        let context = DefaultAlgoContext::for_tests();
        let rows = DefaultAlgoBuilder::default().digest_rows(&context);
        assert!(rows.iter().any(|row| row.name() == "SHA-256"));
    }

    #[cfg(not(feature = "sha256"))]
    #[test]
    fn a_new_builder_has_no_digest_when_no_feature_is_on() {
        assert!(DefaultAlgoBuilder::default().digests.is_empty());
    }

    #[cfg(not(any(feature = "aes", feature = "chacha", feature = "rsa")))]
    #[test]
    fn a_new_builder_has_no_cipher_when_no_feature_is_on() {
        assert!(DefaultAlgoBuilder::default().ciphers.is_empty());
    }
}
