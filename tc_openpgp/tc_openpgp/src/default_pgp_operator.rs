#[cfg(feature = "cfrg-curves")]
use crate::PgpInlineSignatureProvider;
use crate::PgpOperator;
#[cfg(feature = "cfrg-curves")]
use crate::operator::certificate::{PgpCertificateProvider, V6Certificates};
#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
use crate::operator::detached_signature::{
    DefaultDetachedSignatures, PgpDetachedSignatureProvider,
};
#[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
use crate::operator::encrypted_message::{DefaultEncryptedMessages, PgpEncryptedMessageProvider};
use crate::operator::generate::PgpKeyPairGeneratorProvider;
#[cfg(any(feature = "secret-key", feature = "legacy-encryption"))]
use crate::operator::secret_key::{DefaultSecretKeys, PgpSecretKeyProvider};
use crate::operator::serializer::{DefaultPgpPublicKeySerializer, PgpPublicKeySerializer};

pub(crate) struct DefaultPgpOperator {
    #[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
    pub(crate) signatures: DefaultDetachedSignatures,
    #[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
    pub(crate) encrypted_messages: DefaultEncryptedMessages,
    #[cfg(feature = "cfrg-curves")]
    pub(crate) certificates: V6Certificates,
    #[cfg(any(feature = "secret-key", feature = "legacy-encryption"))]
    pub(crate) secret_keys: DefaultSecretKeys,
    pub(crate) generators: Box<dyn PgpKeyPairGeneratorProvider>,
}

impl PgpOperator for DefaultPgpOperator {
    #[cfg(feature = "cfrg-curves")]
    fn inline_signature(&self) -> &dyn PgpInlineSignatureProvider {
        &self.signatures
    }

    #[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
    fn detached_signature(&self) -> &dyn PgpDetachedSignatureProvider {
        &self.signatures
    }
    #[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
    fn encrypted_message(&self) -> &dyn PgpEncryptedMessageProvider {
        &self.encrypted_messages
    }

    #[cfg(feature = "cfrg-curves")]
    fn certificate(&self) -> &dyn PgpCertificateProvider {
        &self.certificates
    }

    #[cfg(any(feature = "secret-key", feature = "legacy-encryption"))]
    fn secret_key(&self) -> &dyn PgpSecretKeyProvider {
        &self.secret_keys
    }

    fn serializer(&self) -> &dyn PgpPublicKeySerializer {
        &DefaultPgpPublicKeySerializer
    }
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        self.generators.as_ref()
    }
}
