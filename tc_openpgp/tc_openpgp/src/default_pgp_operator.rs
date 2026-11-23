use crate::PgpOperator;
#[cfg(feature = "cfrg-curves")]
use crate::operator::certificate::{PgpCertificateProvider, V6Certificates};
#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
use crate::operator::detached_signature::{
    DefaultDetachedSignatures, PgpDetachedSignatureProvider,
};
#[cfg(feature = "encryption")]
use crate::operator::encrypted_message::{PgpEncryptedMessageProvider, X25519EncryptedMessages};
use crate::operator::generate::PgpKeyPairGeneratorProvider;
#[cfg(feature = "secret-key")]
use crate::operator::secret_key::PgpSecretKeyProvider;
use crate::operator::serializer::{DefaultPgpPublicKeySerializer, PgpPublicKeySerializer};

pub(crate) struct DefaultPgpOperator {
    #[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
    pub(crate) signatures: DefaultDetachedSignatures,
    #[cfg(feature = "encryption")]
    pub(crate) encrypted_messages: X25519EncryptedMessages,
    #[cfg(feature = "cfrg-curves")]
    pub(crate) certificates: V6Certificates,
    pub(crate) generators: Box<dyn PgpKeyPairGeneratorProvider>,
}

impl PgpOperator for DefaultPgpOperator {
    #[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
    fn detached_signature(&self) -> &dyn PgpDetachedSignatureProvider {
        &self.signatures
    }
    #[cfg(feature = "encryption")]
    fn encrypted_message(&self) -> &dyn PgpEncryptedMessageProvider {
        &self.encrypted_messages
    }

    #[cfg(feature = "cfrg-curves")]
    fn certificate(&self) -> &dyn PgpCertificateProvider {
        &self.certificates
    }

    #[cfg(feature = "secret-key")]
    fn secret_key(&self) -> &dyn PgpSecretKeyProvider {
        &self.certificates
    }

    fn serializer(&self) -> &dyn PgpPublicKeySerializer {
        &DefaultPgpPublicKeySerializer
    }
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        self.generators.as_ref()
    }
}
