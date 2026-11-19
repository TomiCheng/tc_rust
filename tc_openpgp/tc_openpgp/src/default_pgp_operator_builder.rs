use std::collections::HashMap;
use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::default_pgp_operator::DefaultPgpOperator;
use crate::key_pair_generator::GeneratorFactory;
use crate::{DefaultPgpOperatorContext, PgpKeyPairGenerator, PgpOperator, PgpOperatorBuilder};

/// Builder for the default OpenPGP operator.
#[derive(Clone, Default)]
pub struct DefaultPgpOperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    generators: HashMap<PublicKeyAlgorithmTag, GeneratorFactory>,
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
        self.generators.insert(tag, Arc::new(create));
    }
}

impl PgpOperatorBuilder for DefaultPgpOperatorBuilder {
    fn build(&self) -> Box<dyn PgpOperator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        Box::new(DefaultPgpOperator {
            context: DefaultPgpOperatorContext::new(algo),
            generators: self.generators.clone(),
        })
    }
}
