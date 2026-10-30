//! GOST 28147-89 message authentication code.
//!
//! The convenience [`Gost28147MacParamsRef`] uses the CryptoPro E-A S-box,
//! matching Bouncy Castle's `Gost28147Mac` default. Caller-owned parameter
//! types may implement [`Gost28147Params`] and [`IvParams`] directly.

#![no_std]

use core::fmt;

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_gost28147::{Gost28147Params, KEY_BYTES, s_box};
use tc_macs::{InitError, Mac, MacError, MacInit};

const BLOCK_BYTES: usize = 8;
const TAG_BYTES: usize = 4;
const SUBKEYS: usize = KEY_BYTES / 4;

/// Borrowed GOST 28147 MAC parameters: a key, an S-box and an 8-byte IV.
///
/// An all-zero IV gives Bouncy Castle's form keyed without one.
#[derive(Clone, Copy, Debug)]
pub struct Gost28147MacParamsRef<'a> {
    key: &'a [u8],
    s_box: &'a [u8],
    iv: &'a [u8],
}

impl<'a> Gost28147MacParamsRef<'a> {
    /// Uses the CryptoPro E-A S-box.
    pub const fn new(key: &'a [u8], iv: &'a [u8]) -> Self {
        Self {
            key,
            s_box: &s_box::E_A,
            iv,
        }
    }

    /// Selects an explicit S-box.
    pub const fn with_s_box(mut self, s_box: &'a [u8]) -> Self {
        self.s_box = s_box;
        self
    }
}

impl KeyParams for Gost28147MacParamsRef<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Gost28147Params for Gost28147MacParamsRef<'_> {
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

impl IvParams for Gost28147MacParamsRef<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

/// Allocation-free GOST 28147 MAC.
pub struct Gost28147Mac {
    subkeys: [u32; SUBKEYS],
    s_box: [u8; s_box::BYTES],
    mac: [u8; BLOCK_BYTES],
    buffer: [u8; BLOCK_BYTES],
    buffer_offset: usize,
    iv: [u8; BLOCK_BYTES],
    first_step: bool,
    initialized: bool,
}

impl Gost28147Mac {
    /// Creates an uninitialized GOST 28147 MAC.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            s_box: s_box::E_A,
            mac: [0; BLOCK_BYTES],
            buffer: [0; BLOCK_BYTES],
            buffer_offset: 0,
            iv: [0; BLOCK_BYTES],
            first_step: true,
            initialized: false,
        }
    }

    fn main_step(&self, value: u32, subkey: u32) -> u32 {
        let sum = value.wrapping_add(subkey);
        let mut substituted = 0_u32;
        for row in 0..s_box::ROWS {
            let nibble = ((sum >> (row * 4)) & 0xf) as usize;
            substituted |= u32::from(self.s_box[row * s_box::COLUMNS + nibble]) << (row * 4);
        }
        substituted.rotate_left(11)
    }

    fn mac_block(&self, input: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        let mut n1 = u32::from_le_bytes(input[..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(input[4..].try_into().unwrap());
        for _ in 0..2 {
            for &subkey in &self.subkeys {
                let previous = n1;
                n1 = n2 ^ self.main_step(n1, subkey);
                n2 = previous;
            }
        }

        let mut output = [0_u8; BLOCK_BYTES];
        output[..4].copy_from_slice(&n1.to_le_bytes());
        output[4..].copy_from_slice(&n2.to_le_bytes());
        output
    }

    fn process_buffer(&mut self) {
        let mut sum = self.buffer;
        if self.first_step {
            self.first_step = false;
            for (byte, &iv) in sum.iter_mut().zip(&self.iv) {
                *byte ^= iv;
            }
        } else {
            for (byte, &mac) in sum.iter_mut().zip(&self.mac) {
                *byte ^= mac;
            }
        }
        self.mac = self.mac_block(&sum);
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }

    fn clear_message(&mut self) {
        self.mac.fill(0);
        self.buffer.fill(0);
        self.buffer_offset = 0;
        self.first_step = true;
    }
}

impl Default for Gost28147Mac {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Gost28147Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost28147Mac")
    }
}

impl Mac for Gost28147Mac {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        let gap = BLOCK_BYTES - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..].copy_from_slice(&input[..gap]);
            self.process_buffer();
            input = &input[gap..];
            while input.len() > BLOCK_BYTES {
                self.buffer.copy_from_slice(&input[..BLOCK_BYTES]);
                self.buffer_offset = BLOCK_BYTES;
                self.process_buffer();
                input = &input[BLOCK_BYTES..];
            }
        }
        let end = self.buffer_offset + input.len();
        self.buffer[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
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

        self.buffer[self.buffer_offset..].fill(0);
        let mut sum = self.buffer;
        if self.first_step {
            self.first_step = false;
        } else {
            for (byte, &mac) in sum.iter_mut().zip(&self.mac) {
                *byte ^= mac;
            }
        }
        self.mac = self.mac_block(&sum);
        output[..TAG_BYTES].copy_from_slice(&self.mac[..TAG_BYTES]);
        self.clear_message();
        Ok(TAG_BYTES)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<P> MacInit<P> for Gost28147Mac
where
    P: Gost28147Params + IvParams + ?Sized,
{
    type Error = InitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.clear_message();
        self.subkeys.fill(0);
        self.iv.fill(0);

        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let table = params.s_box();
        if table.len() != s_box::BYTES {
            return Err(InitError::InvalidSBoxLength(table.len()));
        }
        let iv = params.iv();
        if iv.len() != BLOCK_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.iv.copy_from_slice(iv);
        self.mac.copy_from_slice(iv);

        for (word, bytes) in self.subkeys.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        self.s_box.copy_from_slice(table);
        self.initialized = true;
        Ok(())
    }
}

impl Drop for Gost28147Mac {
    fn drop(&mut self) {
        self.subkeys.fill(0);
        self.s_box.fill(0);
        self.mac.fill(0);
        self.buffer.fill(0);
        self.iv.fill(0);
    }
}
