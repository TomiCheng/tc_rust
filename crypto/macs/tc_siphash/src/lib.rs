//! SipHash-c-d message authentication code.
//!
//! The default [`SipHash`] is SipHash-2-4 and produces an 8-byte tag.
//!
//! ```
//! use tc_macs::{Mac, MacInit};
//! use tc_params::KeyRef;
//! use tc_siphash::SipHash;
//!
//! let key = core::array::from_fn::<_, 16, _>(|index| index as u8);
//! let message = core::array::from_fn::<_, 15, _>(|index| index as u8);
//! let mut mac = SipHash::new();
//! mac.init(&KeyRef::new(&key)).unwrap();
//! mac.update(&message).unwrap();
//!
//! let mut tag = [0_u8; 8];
//! mac.do_final(&mut tag).unwrap();
//! assert_eq!(tag, [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1]);
//! ```

#![no_std]

use core::fmt;

use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacError, MacInit, MacInitError};
use tc_params::KeyParams;

/// SipHash key length in bytes.
pub const KEY_BYTES: usize = 16;
/// SipHash authentication-tag length in bytes.
pub const TAG_BYTES: usize = 8;

/// SipHash-c-d, defaulting to SipHash-2-4.
pub struct SipHash {
    compression_rounds: usize,
    finalization_rounds: usize,
    key0: u64,
    key1: u64,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: [u8; 8],
    tail_len: usize,
    message_len: u64,
    initialized: bool,
}

impl SipHash {
    /// Creates an uninitialized SipHash-2-4 instance.
    pub const fn new() -> Self {
        Self::with_rounds(2, 4)
    }

    /// Creates an uninitialized SipHash-c-d instance.
    pub const fn with_rounds(compression_rounds: usize, finalization_rounds: usize) -> Self {
        Self {
            compression_rounds,
            finalization_rounds,
            key0: 0,
            key1: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            tail: [0; 8],
            tail_len: 0,
            message_len: 0,
            initialized: false,
        }
    }

    fn sip_rounds(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.v0 = self.v0.wrapping_add(self.v1);
            self.v2 = self.v2.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(13) ^ self.v0;
            self.v3 = self.v3.rotate_left(16) ^ self.v2;
            self.v0 = self.v0.rotate_left(32);
            self.v2 = self.v2.wrapping_add(self.v1);
            self.v0 = self.v0.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(17) ^ self.v2;
            self.v3 = self.v3.rotate_left(21) ^ self.v0;
            self.v2 = self.v2.rotate_left(32);
        }
    }

    fn process_word(&mut self, word: u64) {
        self.v3 ^= word;
        self.sip_rounds(self.compression_rounds);
        self.v0 ^= word;
    }

    fn reset_state(&mut self) {
        self.v0 = self.key0 ^ 0x736f_6d65_7073_6575;
        self.v1 = self.key1 ^ 0x646f_7261_6e64_6f6d;
        self.v2 = self.key0 ^ 0x6c79_6765_6e65_7261;
        self.v3 = self.key1 ^ 0x7465_6462_7974_6573;
        self.tail.fill(0);
        self.tail_len = 0;
        self.message_len = 0;
    }
}

impl Default for SipHash {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for SipHash {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            output,
            "SipHash-{}-{}",
            self.compression_rounds, self.finalization_rounds
        )
    }
}

impl Mac for SipHash {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        self.message_len = self.message_len.wrapping_add(input.len() as u64);

        if self.tail_len != 0 {
            let take = (8 - self.tail_len).min(input.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&input[..take]);
            self.tail_len += take;
            input = &input[take..];
            if self.tail_len < 8 {
                return Ok(());
            }
            self.process_word(u64::from_le_bytes(self.tail));
            self.tail.fill(0);
            self.tail_len = 0;
        }

        let (words, remainder) = input.as_chunks::<8>();
        for word in words {
            self.process_word(u64::from_le_bytes(*word));
        }
        self.tail[..remainder.len()].copy_from_slice(remainder);
        self.tail_len = remainder.len();
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < TAG_BYTES {
            return Err(MacError::OutputTooShort {
                required: TAG_BYTES,
                available: output.len(),
            });
        }

        let mut final_word = (self.message_len & 0xff) << 56;
        for (index, &byte) in self.tail[..self.tail_len].iter().enumerate() {
            final_word |= u64::from(byte) << (index * 8);
        }
        self.process_word(final_word);
        self.v2 ^= 0xff;
        self.sip_rounds(self.finalization_rounds);
        output[..TAG_BYTES].copy_from_slice(&(self.v0 ^ self.v1 ^ self.v2 ^ self.v3).to_le_bytes());
        self.reset_state();
        Ok(TAG_BYTES)
    }

    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<P: KeyParams + ?Sized> MacInit<P> for SipHash {
    type Error = MacInitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(MacInitError::InvalidKeyLength(key.len()));
        }

        self.key0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        self.key1 = u64::from_le_bytes(key[8..].try_into().unwrap());
        self.initialized = true;
        self.reset_state();
        Ok(())
    }
}

impl Drop for SipHash {
    fn drop(&mut self) {
        self.key0 = 0;
        self.key1 = 0;
        self.v0 = 0;
        self.v1 = 0;
        self.v2 = 0;
        self.v3 = 0;
        self.tail.fill(0);
    }
}
