use super::{DigestProvider, MacProvider};
use crate::digest::EmptyDigestProvider;
use crate::mac::EmptyMacProvider;

pub trait Algo {
    fn digest(&self) -> &dyn DigestProvider {
        &EmptyDigestProvider
    }

    fn mac(&self) -> &dyn MacProvider {
        &EmptyMacProvider
    }
}
