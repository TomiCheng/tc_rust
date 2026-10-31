use core::convert::Infallible;
use core::fmt;

use tc_digest::TryDigest;

use super::dyn_digest::DynDigest;
use super::{Algorithm, DigestEntry};

pub struct AnyDigest {
    entry: &'static DigestEntry,
    digest: Box<dyn DynDigest>,
}

impl AnyDigest {
    pub fn algorithm(&self) -> Algorithm {
        todo!()
    }

    pub fn entry(&self) -> &'static DigestEntry {
        todo!()
    }

    pub fn update(&mut self, input: &[u8]) {
        todo!()
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        todo!()
    }
}

impl Clone for AnyDigest {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl fmt::Debug for AnyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Display for AnyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl TryDigest for AnyDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        todo!()
    }

    fn byte_length(&self) -> usize {
        todo!()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}
