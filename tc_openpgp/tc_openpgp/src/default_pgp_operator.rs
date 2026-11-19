use crate::PgpOperator;
use crate::operator::generate::PgpKeyPairGeneratorProvider;

pub(crate) struct DefaultPgpOperator {
    pub(crate) generators: Box<dyn PgpKeyPairGeneratorProvider>,
}

impl PgpOperator for DefaultPgpOperator {
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        self.generators.as_ref()
    }
}
