use crate::operator::certificate::{EmptyCertificateProvider, PgpCertificateProvider};
use crate::operator::detached_signature::{
    EmptyDetachedSignatureProvider, PgpDetachedSignatureProvider,
};
use crate::operator::encrypted_message::{
    EmptyEncryptedMessageProvider, PgpEncryptedMessageProvider,
};
use crate::operator::generate::{EmptyPgpKeyPairGeneratorProvider, PgpKeyPairGeneratorProvider};

use crate::operator::secret_key::{EmptySecretKeyProvider, PgpSecretKeyProvider};
use crate::operator::serializer::{EmptyPgpPublicKeySerializer, PgpPublicKeySerializer};

pub trait PgpOperator: Send + Sync {
    /// Returns the transferable public key provider.
    fn certificate(&self) -> &dyn PgpCertificateProvider {
        &EmptyCertificateProvider
    }

    fn detached_signature(&self) -> &dyn PgpDetachedSignatureProvider {
        &EmptyDetachedSignatureProvider
    }
    fn encrypted_message(&self) -> &dyn PgpEncryptedMessageProvider {
        &EmptyEncryptedMessageProvider
    }

    /// Returns the password-protected secret key provider.
    fn secret_key(&self) -> &dyn PgpSecretKeyProvider {
        &EmptySecretKeyProvider
    }

    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        &EmptyPgpKeyPairGeneratorProvider
    }

    /// Returns the serializer for a single public key packet.
    fn serializer(&self) -> &dyn PgpPublicKeySerializer {
        &EmptyPgpPublicKeySerializer
    }
}
