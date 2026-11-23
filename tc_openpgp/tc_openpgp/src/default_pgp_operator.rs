use crate::PgpOperator;
use crate::operator::generate::PgpKeyPairGeneratorProvider;
use crate::operator::serializer::{DefaultPgpPublicKeySerializer, PgpPublicKeySerializer};

pub(crate) struct DefaultPgpOperator {
    pub(crate) generators: Box<dyn PgpKeyPairGeneratorProvider>,
}

impl PgpOperator for DefaultPgpOperator {
    fn serializer(&self) -> &dyn PgpPublicKeySerializer {
        &DefaultPgpPublicKeySerializer
    }
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        self.generators.as_ref()
    }
}
