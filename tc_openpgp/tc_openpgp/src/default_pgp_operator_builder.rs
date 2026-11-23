use std::collections::HashMap;
use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::default_pgp_operator::DefaultPgpOperator;
#[cfg(feature = "cfrg-curves")]
use crate::operator::detached_signature::Ed25519DetachedSignatures;
#[cfg(feature = "encryption")]
use crate::operator::encrypted_message::X25519EncryptedMessages;
use crate::operator::generate::{
    BUILT_IN, DefaultPgpKeyPairGeneratorProvider, EmptyPgpKeyPairGeneratorProvider,
    GeneratorFactory, PgpKeyPairGenerator, PgpKeyPairGeneratorProvider,
};
use crate::{DefaultPgpOperatorContext, PgpOperator, PgpOperatorBuilder};

/// Builder for the default OpenPGP operator.
#[derive(Clone)]
pub struct DefaultPgpOperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    generators: HashMap<PublicKeyAlgorithmTag, GeneratorFactory>,
}

impl Default for DefaultPgpOperatorBuilder {
    fn default() -> Self {
        let mut builder = Self {
            algo: None,
            generators: HashMap::new(),
        };
        for &(tag, create) in BUILT_IN {
            builder.generators.insert(tag, Arc::new(create));
        }
        builder
    }
}

impl DefaultPgpOperatorBuilder {
    /// Sets the algorithm provider used by the OpenPGP operator.
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    /// Registers a factory for a tag, replacing any previous registration for it.
    pub fn reg_key_pair_generator(
        &mut self,
        tag: PublicKeyAlgorithmTag,
        create: impl Fn(&DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator>
        + Send
        + Sync
        + 'static,
    ) {
        self.generators
            .insert(tag, Arc::new(move |ctx| Ok(create(ctx))));
    }
}

impl PgpOperatorBuilder for DefaultPgpOperatorBuilder {
    fn build(&self) -> Box<dyn PgpOperator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let generators: Box<dyn PgpKeyPairGeneratorProvider> = if self.generators.is_empty() {
            Box::new(EmptyPgpKeyPairGeneratorProvider)
        } else {
            Box::new(DefaultPgpKeyPairGeneratorProvider {
                context: DefaultPgpOperatorContext::new(algo.clone()),
                generators: self.generators.clone(),
            })
        };
        Box::new(DefaultPgpOperator {
            generators,
            #[cfg(feature = "cfrg-curves")]
            signatures: Ed25519DetachedSignatures { algo: algo.clone() },
            #[cfg(feature = "encryption")]
            encrypted_messages: X25519EncryptedMessages { algo },
        })
    }
}
