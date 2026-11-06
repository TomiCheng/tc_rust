use crate::agreement::{AgreementProvider, EmptyAgreementProvider};
use crate::cipher::{CipherProvider, EmptyCipherProvider};
use crate::digest::{DigestProvider, EmptyDigestProvider};
use crate::generate::{
    EmptyKeyGeneratorProvider, EmptyKeyPairGeneratorProvider, KeyGeneratorProvider,
    KeyPairGeneratorProvider,
};
use crate::kdf::{EmptyKdfProvider, KdfProvider};
use crate::mac::{EmptyMacProvider, MacProvider};
use crate::signer::{EmptySignerProvider, SignerProvider};
use crate::wrap::{EmptyWrapperProvider, WrapperProvider};
use crate::xof::{EmptyXofProvider, XofProvider};

pub trait Algo: Send + Sync {
    fn digest(&self) -> &dyn DigestProvider {
        &EmptyDigestProvider
    }

    fn xof(&self) -> &dyn XofProvider {
        &EmptyXofProvider
    }

    fn mac(&self) -> &dyn MacProvider {
        &EmptyMacProvider
    }

    fn cipher(&self) -> &dyn CipherProvider {
        &EmptyCipherProvider
    }

    fn wrap(&self) -> &dyn WrapperProvider {
        &EmptyWrapperProvider
    }

    fn key_generator(&self) -> &dyn KeyGeneratorProvider {
        &EmptyKeyGeneratorProvider
    }

    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider {
        &EmptyKeyPairGeneratorProvider
    }

    fn agreement(&self) -> &dyn AgreementProvider {
        &EmptyAgreementProvider
    }

    fn signer(&self) -> &dyn SignerProvider {
        &EmptySignerProvider
    }

    fn kdf(&self) -> &dyn KdfProvider {
        &EmptyKdfProvider
    }
}
