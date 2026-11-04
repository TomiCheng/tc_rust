use super::DigestProvider;
use crate::digest::EmptyDigestProvider;

pub trait Algo {
    fn digest(&self) -> &dyn DigestProvider {
        &EmptyDigestProvider
    }
}
