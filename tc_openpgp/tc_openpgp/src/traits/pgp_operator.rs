use crate::PgpKeyPairGeneratorProvider;

pub trait PgpOperator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider;
}
