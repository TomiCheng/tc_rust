//! KMAC128 and KMAC256 (NIST SP 800-185).
//!
//! This crate uses allocation because the underlying cSHAKE implementation
//! retains the function-name/customization prefix and KMAC retains its key for
//! reset. [`KMac`] implements both the fixed-size [`Mac`] API and the
//! extendable-output [`TryXof`] API.
//!
//! [`Mac`]: tc_macs::Mac
//! [`TryXof`]: tc_digest::TryXof

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::{convert::Infallible, fmt};

use tc_crypto::AlgorithmName;
use tc_digest::{Digest, TryDigest, TryXof, Xof};
use tc_keccak::CShakeDigest;
use tc_macs::{Mac, MacError, MacInit};
use tc_params::KeyParams;

const FUNCTION_NAME: &[u8] = b"KMAC";

/// KMAC128 or KMAC256.
pub struct KMac {
    cshake: CShakeDigest,
    bit_length: usize,
    output_length: usize,
    key: Vec<u8>,
    initialized: bool,
    first_output: bool,
}

impl KMac {
    /// Creates KMAC128 or KMAC256 with the supplied customization string.
    ///
    /// # Panics
    ///
    /// Panics unless `bit_length` is 128 or 256.
    pub fn new(bit_length: usize, customization: &[u8]) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "KMAC bit length must be 128 or 256"
        );
        Self {
            cshake: CShakeDigest::new(bit_length, FUNCTION_NAME, customization),
            bit_length,
            output_length: bit_length / 4,
            key: Vec::new(),
            initialized: false,
            first_output: true,
        }
    }

    /// Starts or continues KMACXOF output.
    pub fn output(&mut self, output: &mut [u8]) -> Result<usize, MacError> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if self.first_output {
            let (encoding, count) = right_encode(0);
            self.cshake.update(&encoding[..count]);
            self.first_output = false;
        }
        Ok(self.cshake.output(output))
    }

    /// Finishes fixed-length output, or finishes a KMACXOF stream after
    /// [`output`](Self::output), then resets to the initialized key.
    pub fn output_final(&mut self, output: &mut [u8]) -> Result<usize, MacError> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if self.first_output {
            let output_bits = (output.len() as u64).wrapping_mul(8);
            let (encoding, count) = right_encode(output_bits);
            self.cshake.update(&encoding[..count]);
        }
        let written = self.cshake.output_final(output);
        self.reset_state();
        Ok(written)
    }

    fn reset_state(&mut self) {
        self.cshake.reset();
        self.first_output = true;
        if self.initialized {
            let rate = self.cshake.byte_length();
            let (width, width_len) = left_encode(rate as u64);
            let key_bits = (self.key.len() as u64).wrapping_mul(8);
            let (key_length, key_length_len) = left_encode(key_bits);
            self.cshake.update(&width[..width_len]);
            self.cshake.update(&key_length[..key_length_len]);
            self.cshake.update(&self.key);

            let used = width_len + key_length_len + self.key.len();
            let remainder = used % rate;
            if remainder != 0 {
                let zeros = [0_u8; 168];
                self.cshake.update(&zeros[..rate - remainder]);
            }
        }
    }
}

impl AlgorithmName for KMac {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        write!(output, "KMAC{}", self.bit_length)
    }
}

impl Mac for KMac {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        self.output_length
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        self.cshake.update(input);
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.output_length {
            return Err(MacError::OutputTooShort {
                required: self.output_length,
                available: output.len(),
            });
        }
        self.output_final(&mut output[..self.output_length])
    }

    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<P: KeyParams + ?Sized> MacInit<P> for KMac {
    type Error = Infallible;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.key.fill(0);
        self.key.clear();
        self.key.extend_from_slice(params.key());
        self.initialized = true;
        self.reset_state();
        Ok(())
    }
}

impl TryDigest for KMac {
    type Error = MacError;

    fn algorithm_name(&self) -> &str {
        if self.bit_length == 128 {
            "KMAC128"
        } else {
            "KMAC256"
        }
    }

    fn digest_size(&self) -> usize {
        self.output_length
    }

    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Mac::update(self, input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        Mac::do_final(self, output)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        Mac::reset(self);
        Ok(())
    }
}

impl TryXof for KMac {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output(output)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output_final(output)
    }
}

impl Drop for KMac {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

fn left_encode(value: u64) -> ([u8; 9], usize) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let length = 8 - first;
    let mut output = [0_u8; 9];
    output[0] = length as u8;
    output[1..=length].copy_from_slice(&bytes[first..]);
    (output, length + 1)
}

fn right_encode(value: u64) -> ([u8; 9], usize) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let length = 8 - first;
    let mut output = [0_u8; 9];
    output[..length].copy_from_slice(&bytes[first..]);
    output[length] = length as u8;
    (output, length + 1)
}
