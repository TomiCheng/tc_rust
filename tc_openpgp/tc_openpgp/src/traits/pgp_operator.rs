use crate::operator::generate::{EmptyPgpKeyPairGeneratorProvider, PgpKeyPairGeneratorProvider};

use crate::operator::serializer::{EmptyPgpPublicKeySerializer, PgpPublicKeySerializer};

pub trait PgpOperator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        &EmptyPgpKeyPairGeneratorProvider
    }

    /// Returns the serializer for a single public key packet.
    fn serializer(&self) -> &dyn PgpPublicKeySerializer {
        &EmptyPgpPublicKeySerializer
    }
}
