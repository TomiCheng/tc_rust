use core::convert::Infallible;
use core::fmt;
use std::sync::Arc;

use tc_digest::TryDigest;

use crate::digest::{Digest, DigestEntry};

// A digest row as the infallible digest that the MACs and signers of tc_macs, tc_rsa_signer and
// tc_dsa take. A row fails only to write into an output shorter than its size, which they never
// give it, and Haraka, which takes inputs of one length alone, is left to the callers to skip. Its
// name is the row's, as the signers find their trailers by it. A clone is a new digest of the row:
// the signers clone it only before any input
pub(crate) struct RowDigest {
    entry: Arc<dyn DigestEntry>,
    digest: Box<dyn Digest>,
}

impl RowDigest {
    pub(crate) fn new(entry: Arc<dyn DigestEntry>) -> Self {
        let digest = entry.create();
        Self { entry, digest }
    }
}

impl Clone for RowDigest {
    fn clone(&self) -> Self {
        Self::new(self.entry.clone())
    }
}

impl fmt::Display for RowDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}

const INFALLIBLE: &str = "a digest row other than Haraka fails only on a short output";

impl TryDigest for RowDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.digest.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.digest.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Infallible> {
        self.digest.try_update(input).expect(INFALLIBLE);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Infallible> {
        Ok(self.digest.try_do_final(output).expect(INFALLIBLE))
    }

    fn try_reset(&mut self) -> Result<(), Infallible> {
        self.digest.try_reset().expect(INFALLIBLE);
        Ok(())
    }
}
