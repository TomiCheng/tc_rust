use crate::operator::generate::{EmptyPgpKeyPairGeneratorProvider, PgpKeyPairGeneratorProvider};

pub trait PgpOperator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        &EmptyPgpKeyPairGeneratorProvider
    }
}
