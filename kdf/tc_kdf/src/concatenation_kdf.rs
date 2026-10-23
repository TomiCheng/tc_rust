use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use tc_digest::Digest;
use tc_zeroize::Zeroize;

use crate::{Kdf, KdfError, KdfInit, KdfParams};

/// The concatenation KDF of NIST SP 800-56A section 5.8.1, BC's `ConcatenationKdfGenerator`:
/// block `i` is `Hash(counter || Z || OtherInfo)` with a 32-bit big-endian counter starting
/// at 1. The [`KdfParams`] IV is the `OtherInfo`.
///
/// Every call to `generate_bytes` starts over from the first block, as in BC. The secret and
/// `OtherInfo` copied at `init` are wiped when replaced and on drop.
pub struct ConcatenationKdf<D> {
    digest: D,
    shared_secret: Option<Vec<u8>>,
    other_info: Vec<u8>,
}

impl<D> ConcatenationKdf<D> {
    /// A function over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            shared_secret: None,
            other_info: Vec::new(),
        }
    }
}

impl<D, P: KdfParams + ?Sized> KdfInit<P> for ConcatenationKdf<D> {
    type Error = Infallible;

    /// Copies the shared secret and `OtherInfo`. Any secret is accepted, as in BC. Constant
    /// time with respect to their contents.
    fn init(&mut self, params: &P) -> Result<(), Infallible> {
        self.shared_secret.zeroize();
        self.other_info.zeroize();
        self.shared_secret = Some(params.shared_secret().to_vec());
        self.other_info = params.iv().to_vec();
        Ok(())
    }
}

impl<D: Digest> Kdf for ConcatenationKdf<D> {
    type Error = KdfError;

    /// Fills `output` from the first block on. Fails before `init`, or when `output` is longer
    /// than `(2^32 - 1) * digest size` bytes, the limit of SP 800-56A that BC leaves unchecked.
    /// Constant time with respect to the secret when the digest is; the output length is
    /// public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, KdfError> {
        let shared_secret = self
            .shared_secret
            .as_deref()
            .ok_or(KdfError::NotInitialised)?;
        let digest_size = self.digest.digest_size();
        if output.len() as u64 > u64::from(u32::MAX) * digest_size as u64 {
            return Err(KdfError::OutputTooLong);
        }
        self.digest.reset();
        if output.is_empty() {
            return Ok(0);
        }

        let mut counter = 1u32;
        let mut last = Vec::new();
        for block in output.chunks_mut(digest_size) {
            self.digest.update(&counter.to_be_bytes());
            self.digest.update(shared_secret);
            self.digest.update(&self.other_info);
            if block.len() == digest_size {
                self.digest.do_final(block);
            } else {
                last = vec![0; digest_size];
                self.digest.do_final(&mut last);
                block.copy_from_slice(&last[..block.len()]);
            }
            counter = counter.wrapping_add(1);
        }
        last.zeroize();
        Ok(output.len())
    }
}

impl<D> Drop for ConcatenationKdf<D> {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
        self.other_info.zeroize();
    }
}
