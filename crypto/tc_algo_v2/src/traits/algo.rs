use super::{DigestProvider, KeyGeneratorProvider, KeyPairGeneratorProvider, MacProvider};
use crate::digest::EmptyDigestProvider;
use crate::generate::{EmptyKeyGeneratorProvider, EmptyKeyPairGeneratorProvider};
use crate::mac::EmptyMacProvider;

pub trait Algo {
    fn digest(&self) -> &dyn DigestProvider {
        &EmptyDigestProvider
    }

    fn mac(&self) -> &dyn MacProvider {
        &EmptyMacProvider
    }

    fn key_generator(&self) -> &dyn KeyGeneratorProvider {
        &EmptyKeyGeneratorProvider
    }

    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider {
        &EmptyKeyPairGeneratorProvider
    }
}
