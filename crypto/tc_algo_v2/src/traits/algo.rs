use crate::cipher::{CipherProvider, EmptyCipherProvider};
use crate::digest::{EmptyDigestProvider, DigestProvider};
use crate::generate::{
    EmptyKeyGeneratorProvider, EmptyKeyPairGeneratorProvider, KeyGeneratorProvider,
    KeyPairGeneratorProvider,
};
use crate::mac::{EmptyMacProvider, MacProvider};
use crate::wrap::{EmptyWrapperProvider, WrapperProvider};

pub trait Algo {
    fn digest(&self) -> &dyn DigestProvider {
        &EmptyDigestProvider
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
}
