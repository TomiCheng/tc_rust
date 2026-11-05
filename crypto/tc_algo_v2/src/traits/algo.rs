use super::{KeyGeneratorProvider, KeyPairGeneratorProvider, MacProvider};
use crate::cipher::{CipherProvider, EmptyCipherProvider};
use crate::digest::{EmptyDigestProvider, DigestProvider};
use crate::generate::{EmptyKeyGeneratorProvider, EmptyKeyPairGeneratorProvider};
use crate::mac::EmptyMacProvider;

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

    fn key_generator(&self) -> &dyn KeyGeneratorProvider {
        &EmptyKeyGeneratorProvider
    }

    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider {
        &EmptyKeyPairGeneratorProvider
    }
}
