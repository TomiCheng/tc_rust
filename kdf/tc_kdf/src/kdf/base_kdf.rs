use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use tc_digest::Digest;
use tc_zeroize::Zeroize;

use crate::kdf::KdfParams;
use crate::{Kdf, KdfError, KdfInit};

/// KDF1 (ISO 18033-2): the counter starts at 0.
pub type Kdf1<D> = BaseKdf<D, 0>;

/// KDF2 (ISO 18033-2, also ANSI X9.63 and IEEE P1363a's KDF2): the counter starts at 1.
pub type Kdf2<D> = BaseKdf<D, 1>;

/// BC's `BaseKdfBytesGenerator`: block `i` is `Hash(Z || counter || IV)` with a 32-bit
/// big-endian counter starting at `COUNTER_START`.
///
/// Every call to `generate_bytes` starts over from the first block, as in BC. The secret and
/// IV copied at `init` are wiped when replaced and on drop.
pub struct BaseKdf<D, const COUNTER_START: u32> {
    digest: D,
    shared_secret: Option<Vec<u8>>,
    iv: Vec<u8>,
}

impl<D, const COUNTER_START: u32> BaseKdf<D, COUNTER_START> {
    /// A function over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            shared_secret: None,
            iv: Vec::new(),
        }
    }
}

impl<D, P, const COUNTER_START: u32> KdfInit<P> for BaseKdf<D, COUNTER_START>
where
    P: KdfParams + ?Sized,
{
    type Error = Infallible;

    /// Copies the shared secret and IV. Any secret is accepted, as in BC. Constant time with
    /// respect to their contents.
    fn init(&mut self, params: &P) -> Result<(), Infallible> {
        self.shared_secret.zeroize();
        self.iv.zeroize();
        self.shared_secret = Some(params.shared_secret().to_vec());
        self.iv = params.iv().to_vec();
        Ok(())
    }
}

impl<D: Digest, const COUNTER_START: u32> Kdf for BaseKdf<D, COUNTER_START> {
    type Error = KdfError;

    /// Fills `output` from the first block on. Fails before `init`, or when `output` is longer
    /// than `(2^32 - 1) * digest size` bytes. Constant time with respect to the secret when the
    /// digest is; the output length is public.
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

        let mut counter = COUNTER_START;
        let mut last = Vec::new();
        for block in output.chunks_mut(digest_size) {
            self.digest.update(shared_secret);
            self.digest.update(&counter.to_be_bytes());
            self.digest.update(&self.iv);
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

impl<D, const COUNTER_START: u32> Drop for BaseKdf<D, COUNTER_START> {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
        self.iv.zeroize();
    }
}
