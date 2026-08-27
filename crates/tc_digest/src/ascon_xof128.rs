//! Ascon-XOF128 from NIST SP 800-232, ported from Bouncy Castle's `AsconXof128`.
//!
//! The non-customizable sibling of [`AsconCXof128`](crate::ascon_cxof128): the same
//! Ascon-p\[12] sponge XOF with an 8-byte rate, but a fixed initial state and no
//! customization string.

use core::convert::Infallible;

use tc_crypto_core::{TryDigest, TryXof};

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;

// 初始狀態(bc 快取值 = P12(seed 0x0000080000cc0003))。
const IV: [u64; 5] = [
    0xda82_ce76_8d94_47eb,
    0xcc7c_e6c7_5f1e_f969,
    0xe750_8fd7_8008_5631,
    0x0ee0_ea53_416b_58cc,
    0xe054_7524_db6f_0bde,
];

/// The 256-bit Ascon XOF (Ascon-XOF128) from NIST SP 800-232.
#[derive(Clone)]
pub struct AsconXof128 {
    state: [u64; 5],
    /// 吸收階段為輸入緩衝;擠出階段為當前輸出區塊。
    buffer: [u8; RATE],
    /// 吸收階段 = 已填位元組;擠出階段 = 當前輸出區塊已消耗位元組(8 = 需再置換)。
    buffer_position: usize,
    squeezing: bool,
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconXof128 {
    /// Creates a new Ascon-XOF128.
    pub fn new() -> Self {
        AsconXof128 {
            state: IV,
            buffer: [0; RATE],
            buffer_position: 0,
            squeezing: false,
        }
    }

    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_le_bytes(*block);
        p12(&mut self.state);
    }

    /// 吸收收尾:殘留緩衝 + `0x01` pad XOR 進 S0(不置換)。
    fn pad(&mut self) {
        let mut last = [0u8; RATE];
        last[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        last[self.buffer_position] = 0x01;
        self.state[0] ^= u64::from_le_bytes(last);
    }
}

impl TryDigest for AsconXof128 {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Ascon-XOF128"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        assert!(!self.squeezing, "Ascon-XOF128: attempt to absorb while squeezing");
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = RATE - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == RATE {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().expect("8-byte Ascon block");
            self.absorb_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.try_output_final(&mut output[..DIGEST_LENGTH])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = IV;
        self.buffer = [0; RATE];
        self.buffer_position = 0;
        self.squeezing = false;
        Ok(())
    }
}

impl TryXof for AsconXof128 {
    fn try_output(&mut self, mut output: &mut [u8]) -> Result<usize, Self::Error> {
        let total = output.len();

        if !self.squeezing {
            self.pad();
            self.squeezing = true;
            self.buffer_position = RATE;
        } else if self.buffer_position < RATE {
            let available = RATE - self.buffer_position;
            if output.len() <= available {
                let end = self.buffer_position + output.len();
                output.copy_from_slice(&self.buffer[self.buffer_position..end]);
                self.buffer_position = end;
                return Ok(total);
            }
            output[..available].copy_from_slice(&self.buffer[self.buffer_position..RATE]);
            output = &mut output[available..];
            self.buffer_position = RATE;
        }

        while output.len() >= RATE {
            p12(&mut self.state);
            output[..RATE].copy_from_slice(&self.state[0].to_le_bytes());
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            p12(&mut self.state);
            self.buffer = self.state[0].to_le_bytes();
            let n = output.len();
            output.copy_from_slice(&self.buffer[..n]);
            self.buffer_position = n;
        }

        Ok(total)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_crypto_core::{Digest, Xof};

    #[test]
    fn accessors() {
        let d = AsconXof128::new();
        assert_eq!(d.algorithm_name(), "Ascon-XOF128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 8);
    }

    // 自洽驗證:IV == P12(seed 0x0000080000cc0003)(bc 註解記載的初始化)。
    #[test]
    fn iv_matches_seed_derivation() {
        let mut s = [0x0000_0800_00cc_0003u64, 0, 0, 0, 0];
        p12(&mut s);
        assert_eq!(s, IV);
    }

    #[test]
    fn output_final_resets() {
        let mut a = AsconXof128::new();
        a.update(b"first");
        let mut o1 = [0u8; 32];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = [0u8; 32];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }

    #[test]
    fn streamed_output_matches_single() {
        let mut a = AsconXof128::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 100];
        a.output(&mut whole);

        let mut b = AsconXof128::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 100];
        let (mut off, sizes) = (0usize, [1usize, 7, 8, 9, 3, 40, 32]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        assert_eq!(whole, streamed);
    }
}
