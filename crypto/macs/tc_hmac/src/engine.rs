//! HMAC engine.

use alloc::{vec, vec::Vec};
use core::{convert::Infallible, fmt};

use tc_crypto::AlgorithmName;
use tc_digest::{Digest, TryDigest};
use tc_macs::{Mac, MacError, MacInit};
use tc_params::KeyParams;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const MINIMUM_BLOCK_LENGTH: usize = 16;

/// HMAC over the digest `D`.
///
/// The engine keeps the keyed inner and outer pads so that successful
/// finalization and [`reset`](Mac::reset) retain the most recently initialized
/// key. It deliberately does not require `D: Clone`: after finalization it
/// restores the inner state by resetting the digest and feeding the inner pad
/// again, matching Bouncy Castle's fallback for non-memoable digests.
pub struct HMac<D> {
    digest: D,
    digest_size: usize,
    block_length: usize,
    input_pad: Vec<u8>,
    output_buffer: Vec<u8>,
    initialized: bool,
}

impl<D> HMac<D> {
    /// Returns the digest used by this HMAC.
    pub const fn underlying_digest(&self) -> &D {
        &self.digest
    }

    fn clear_key_material(&mut self) {
        self.input_pad.fill(0);
        self.output_buffer.fill(0);
    }
}

impl<D: Digest> HMac<D> {
    /// Creates an uninitialized HMAC using the digest's reported block size.
    ///
    /// # Panics
    ///
    /// Panics if the digest reports a block size shorter than 16 bytes or a
    /// digest size larger than its block size.
    pub fn new(digest: D) -> Self {
        let block_length = digest.byte_length();
        Self::with_block_length(digest, block_length)
    }

    /// Creates an uninitialized HMAC with an explicit digest block size.
    ///
    /// This corresponds to Bouncy Castle's constructor overload that accepts
    /// a block length. Most callers should use [`new`](Self::new).
    ///
    /// # Panics
    ///
    /// Panics if `block_length` is shorter than 16 bytes or shorter than the
    /// digest output.
    pub fn with_block_length(digest: D, block_length: usize) -> Self {
        let digest_size = digest.digest_size();
        assert!(
            block_length >= MINIMUM_BLOCK_LENGTH,
            "HMAC block length must be at least 16 bytes"
        );
        assert!(
            digest_size <= block_length,
            "HMAC digest size must not exceed its block length"
        );

        Self {
            digest,
            digest_size,
            block_length,
            input_pad: vec![0; block_length],
            output_buffer: vec![0; block_length + digest_size],
            initialized: false,
        }
    }

    fn restore_inner_state(&mut self) {
        self.digest.reset();
        if self.initialized {
            self.digest.update(&self.input_pad);
        }
    }
}

impl<D: TryDigest> AlgorithmName for HMac<D> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str(self.digest.algorithm_name())?;
        output.write_str("/HMAC")
    }
}

impl<D: Digest> Mac for HMac<D> {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        self.digest_size
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        self.digest.update(input);
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.digest_size {
            return Err(MacError::OutputTooShort {
                required: self.digest_size,
                available: output.len(),
            });
        }

        let inner_hash = &mut self.output_buffer[self.block_length..];
        let inner_length = self.digest.do_final(inner_hash);
        debug_assert_eq!(inner_length, self.digest_size);

        self.digest.update(&self.output_buffer);
        let written = self.digest.do_final(output);
        debug_assert_eq!(written, self.digest_size);

        self.output_buffer[self.block_length..].fill(0);
        self.restore_inner_state();
        Ok(written)
    }

    fn reset(&mut self) {
        self.restore_inner_state();
    }
}

impl<D, P> MacInit<P> for HMac<D>
where
    D: Digest,
    P: KeyParams + ?Sized,
{
    type Error = Infallible;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.digest.reset();
        self.clear_key_material();

        let key = params.key();
        let key_length = if key.len() > self.block_length {
            self.digest.update(key);
            let written = self.digest.do_final(&mut self.input_pad);
            debug_assert_eq!(written, self.digest_size);
            self.digest_size
        } else {
            self.input_pad[..key.len()].copy_from_slice(key);
            key.len()
        };
        self.input_pad[key_length..].fill(0);

        self.output_buffer[..self.block_length].copy_from_slice(&self.input_pad);
        for byte in &mut self.input_pad {
            *byte ^= IPAD;
        }
        for byte in &mut self.output_buffer[..self.block_length] {
            *byte ^= OPAD;
        }

        self.initialized = true;
        self.digest.update(&self.input_pad);
        Ok(())
    }
}

impl<D> Drop for HMac<D> {
    fn drop(&mut self) {
        self.clear_key_material();
    }
}
