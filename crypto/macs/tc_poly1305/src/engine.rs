//! Raw Poly1305 engine.

use core::fmt;

use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacError, MacInit, MacInitError};
use tc_params::KeyParams;

use crate::{BLOCK_BYTES, KEY_BYTES, TAG_BYTES};

const LIMB_MASK: u32 = 0x03ff_ffff;
const FULL_BLOCK_HIGH_BIT: u32 = 1 << 24;

/// Raw Poly1305 message authentication code.
///
/// Initialization accepts any [`KeyParams`] implementation that supplies a
/// 32-byte one-time key. No Poly1305-specific parameter wrapper is required.
///
/// # Security
///
/// A Poly1305 key must never authenticate two different messages. Successful
/// finalization and [`reset`](Mac::reset) preserve the initialized key;
/// callers must initialize a fresh one-time key before authenticating another
/// message.
#[derive(Clone)]
pub struct Engine {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    k0: u32,
    k1: u32,
    k2: u32,
    k3: u32,
    block: [u8; BLOCK_BYTES],
    block_offset: usize,
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    initialized: bool,
}

impl Engine {
    /// Creates an uninitialized Poly1305 engine.
    pub const fn new() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            r4: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            k0: 0,
            k1: 0,
            k2: 0,
            k3: 0,
            block: [0; BLOCK_BYTES],
            block_offset: 0,
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            initialized: false,
        }
    }

    #[inline]
    fn load_u32(input: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ])
    }

    fn clear_key(&mut self) {
        self.r0 = 0;
        self.r1 = 0;
        self.r2 = 0;
        self.r3 = 0;
        self.r4 = 0;
        self.s1 = 0;
        self.s2 = 0;
        self.s3 = 0;
        self.s4 = 0;
        self.k0 = 0;
        self.k1 = 0;
        self.k2 = 0;
        self.k3 = 0;
    }

    fn set_key(&mut self, key: &[u8; KEY_BYTES]) {
        let t0 = Self::load_u32(key, 0);
        let t1 = Self::load_u32(key, 4);
        let t2 = Self::load_u32(key, 8);
        let t3 = Self::load_u32(key, 12);

        // These masks perform the Poly1305 key clamp without modifying the
        // caller's key bytes.
        self.r0 = t0 & 0x03ff_ffff;
        self.r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
        self.r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
        self.r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
        self.r4 = (t3 >> 8) & 0x000f_ffff;

        self.s1 = self.r1 * 5;
        self.s2 = self.r2 * 5;
        self.s3 = self.r3 * 5;
        self.s4 = self.r4 * 5;

        self.k0 = Self::load_u32(key, 16);
        self.k1 = Self::load_u32(key, 20);
        self.k2 = Self::load_u32(key, 24);
        self.k3 = Self::load_u32(key, 28);
    }

    fn process_block(&mut self, block: &[u8], high_bit: u32) {
        let t0 = Self::load_u32(block, 0);
        let t1 = Self::load_u32(block, 4);
        let t2 = Self::load_u32(block, 8);
        let t3 = Self::load_u32(block, 12);

        self.h0 += t0 & LIMB_MASK;
        self.h1 += ((t1 << 6) | (t0 >> 26)) & LIMB_MASK;
        self.h2 += ((t2 << 12) | (t1 >> 20)) & LIMB_MASK;
        self.h3 += ((t3 << 18) | (t2 >> 14)) & LIMB_MASK;
        self.h4 += high_bit | (t3 >> 8);

        let tp0 = u64::from(self.h0) * u64::from(self.r0)
            + u64::from(self.h1) * u64::from(self.s4)
            + u64::from(self.h2) * u64::from(self.s3)
            + u64::from(self.h3) * u64::from(self.s2)
            + u64::from(self.h4) * u64::from(self.s1);
        let mut tp1 = u64::from(self.h0) * u64::from(self.r1)
            + u64::from(self.h1) * u64::from(self.r0)
            + u64::from(self.h2) * u64::from(self.s4)
            + u64::from(self.h3) * u64::from(self.s3)
            + u64::from(self.h4) * u64::from(self.s2);
        let mut tp2 = u64::from(self.h0) * u64::from(self.r2)
            + u64::from(self.h1) * u64::from(self.r1)
            + u64::from(self.h2) * u64::from(self.r0)
            + u64::from(self.h3) * u64::from(self.s4)
            + u64::from(self.h4) * u64::from(self.s3);
        let mut tp3 = u64::from(self.h0) * u64::from(self.r3)
            + u64::from(self.h1) * u64::from(self.r2)
            + u64::from(self.h2) * u64::from(self.r1)
            + u64::from(self.h3) * u64::from(self.r0)
            + u64::from(self.h4) * u64::from(self.s4);
        let mut tp4 = u64::from(self.h0) * u64::from(self.r4)
            + u64::from(self.h1) * u64::from(self.r3)
            + u64::from(self.h2) * u64::from(self.r2)
            + u64::from(self.h3) * u64::from(self.r1)
            + u64::from(self.h4) * u64::from(self.r0);

        self.h0 = tp0 as u32 & LIMB_MASK;
        tp1 += tp0 >> 26;
        self.h1 = tp1 as u32 & LIMB_MASK;
        tp2 += tp1 >> 26;
        self.h2 = tp2 as u32 & LIMB_MASK;
        tp3 += tp2 >> 26;
        self.h3 = tp3 as u32 & LIMB_MASK;
        tp4 += tp3 >> 26;
        self.h4 = tp4 as u32 & LIMB_MASK;
        self.h0 += (tp4 >> 26) as u32 * 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
    }

    fn write_tag(&mut self, output: &mut [u8]) {
        self.h0 += 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
        self.h2 += self.h1 >> 26;
        self.h1 &= LIMB_MASK;
        self.h3 += self.h2 >> 26;
        self.h2 &= LIMB_MASK;
        self.h4 += self.h3 >> 26;
        self.h3 &= LIMB_MASK;

        let mut carry = (i64::from(self.h4 >> 26) - 1) * 5;
        carry += i64::from(self.k0) + i64::from(self.h0 | (self.h1 << 26));
        output[..4].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k1) + i64::from((self.h1 >> 6) | (self.h2 << 20));
        output[4..8].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k2) + i64::from((self.h2 >> 12) | (self.h3 << 14));
        output[8..12].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k3) + i64::from((self.h3 >> 18) | (self.h4 << 8));
        output[12..TAG_BYTES].copy_from_slice(&(carry as u32).to_le_bytes());
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("Poly1305")
    }
}

impl Mac for Engine {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        if self.block_offset != 0 {
            let available = BLOCK_BYTES - self.block_offset;
            let take = available.min(input.len());
            self.block[self.block_offset..self.block_offset + take].copy_from_slice(&input[..take]);
            self.block_offset += take;
            input = &input[take..];

            if self.block_offset < BLOCK_BYTES {
                return Ok(());
            }

            let block = self.block;
            self.process_block(&block, FULL_BLOCK_HIGH_BIT);
            self.block_offset = 0;
        }

        while input.len() >= BLOCK_BYTES {
            self.process_block(&input[..BLOCK_BYTES], FULL_BLOCK_HIGH_BIT);
            input = &input[BLOCK_BYTES..];
        }

        self.block[..input.len()].copy_from_slice(input);
        self.block_offset = input.len();
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

        if self.block_offset != 0 {
            let mut block = self.block;
            block[self.block_offset] = 1;
            block[self.block_offset + 1..].fill(0);
            self.process_block(&block, 0);
        }

        debug_assert_eq!(self.h4 >> 26, 0);
        self.write_tag(output);
        self.reset();
        Ok(TAG_BYTES)
    }

    fn reset(&mut self) {
        self.block.fill(0);
        self.block_offset = 0;
        self.h0 = 0;
        self.h1 = 0;
        self.h2 = 0;
        self.h3 = 0;
        self.h4 = 0;
    }
}

impl<P> MacInit<P> for Engine
where
    P: KeyParams + ?Sized,
{
    type Error = MacInitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset();
        self.clear_key();

        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| MacInitError::InvalidKeyLength(key.len()))?;

        self.set_key(key);
        self.initialized = true;
        self.reset();
        Ok(())
    }
}
