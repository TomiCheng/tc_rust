use core::convert::Infallible;
use core::fmt;

use tc_digest::TryDigest;

use super::dyn_digest::DynDigest;
use super::{Algorithm, DigestEntry};

pub struct AnyDigest {
    pub(super) entry: &'static DigestEntry,
    pub(super) digest: Box<dyn DynDigest>,
}

impl AnyDigest {
    pub fn algorithm(&self) -> Algorithm {
        self.entry.algorithm()
    }

    pub fn entry(&self) -> &'static DigestEntry {
        self.entry
    }

    pub fn update(&mut self, input: &[u8]) {
        self.digest.update(input);
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        let mut output = vec![0; self.digest.digest_size()];
        let written = self.digest.do_final(&mut output);
        output.truncate(written);
        output
    }
}

impl Clone for AnyDigest {
    fn clone(&self) -> Self {
        Self {
            entry: self.entry,
            digest: self.digest.clone_box(),
        }
    }
}

// Shows only the algorithm, never the digest's internal state
impl fmt::Debug for AnyDigest {
    #[allow(
        unreachable_code,
        reason = "Algorithm has no values when every digest feature is off"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyDigest")
            .field("algorithm", &self.entry.algorithm())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}

impl TryDigest for AnyDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.digest.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.digest.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.digest.try_update(input)
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.digest.try_update_byte(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.digest.try_do_final(output)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.digest.try_reset()
    }
}
