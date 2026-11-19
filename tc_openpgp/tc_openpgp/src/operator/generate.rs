use std::sync::Arc;

use crate::DefaultPgpOperatorContext;

mod default_pgp_key_pair_generator_provider;
mod empty_pgp_key_pair_generator_provider;
mod pgp_key_pair_generator;
mod pgp_key_pair_generator_provider;

pub(crate) use default_pgp_key_pair_generator_provider::DefaultPgpKeyPairGeneratorProvider;
pub(crate) use empty_pgp_key_pair_generator_provider::EmptyPgpKeyPairGeneratorProvider;
pub use pgp_key_pair_generator::PgpKeyPairGenerator;
pub use pgp_key_pair_generator_provider::PgpKeyPairGeneratorProvider;

pub(crate) type GeneratorFactory =
    Arc<dyn Fn(&DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator> + Send + Sync>;
