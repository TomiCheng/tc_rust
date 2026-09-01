//! Ascon v1.2 XOF (`AsconXof` / `AsconXofA`), ported from Bouncy Castle's
//! deprecated `AsconXof`.
//!
//! **Deprecated.** These are the pre-standardization Ascon v1.2 extendable-output
//! functions, kept only for interoperability with legacy data. For new designs use
//! the NIST SP 800-232 [`AsconXof128`](crate::ascon_xof128::AsconXof128) or
//! [`AsconCXof128`](crate::ascon_cxof128::AsconCXof128).
//!
//! Unlike the SP 800-232 variants (little-endian, `0x01` pad, `p12` throughout),
//! the v1.2 XOF is **big-endian** with an `0x80` pad and a variant-dependent number
//! of permutation rounds: `AsconXof` uses `p12` and `AsconXofA` uses `p8` for
//! absorption and continued squeezing — but the *first* squeeze permutation is
//! always the full `p12`.

#![allow(deprecated)]

use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};

use crate::ascon_core::{p8, p12};

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;

/// Selects between the two Ascon v1.2 XOF variants.
#[deprecated(note = "Ascon v1.2 is superseded by NIST SP 800-232; use AsconXof128 / AsconCXof128")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AsconXofParameters {
    /// Ascon-Xof (12-round `p_b`).
    AsconXof,
    /// Ascon-XofA (8-round `p_b`).
    AsconXofA,
}

const XOF_IV: [u64; 5] = [
    13077933504456348694,
    3121280575360345120,
    7395939140700676632,
    6533890155656471820,
    5710016986865767350,
];
const XOFA_IV: [u64; 5] = [
    4940560291654768690,
    14811614245468591410,
    17849209150987444521,
    2623493988082852443,
    12162917349548726079,
];

const fn initial_state(parameters: AsconXofParameters) -> [u64; 5] {
    match parameters {
        AsconXofParameters::AsconXof => XOF_IV,
        AsconXofParameters::AsconXofA => XOFA_IV,
    }
}

/// The deprecated Ascon v1.2 extendable-output function.
#[deprecated(note = "Ascon v1.2 is superseded by NIST SP 800-232; use AsconXof128 / AsconCXof128")]
#[derive(Clone)]
pub struct AsconXof {
    parameters: AsconXofParameters,
    state: [u64; 5],
    buffer: [u8; RATE],
    buffer_position: usize,
    squeezing: bool,
}

impl AsconXof {
    /// Creates a new Ascon v1.2 XOF of the given variant.
    pub fn new(parameters: AsconXofParameters) -> Self {
        AsconXof {
            parameters,
            state: initial_state(parameters),
            buffer: [0; RATE],
            buffer_position: 0,
            squeezing: false,
        }
    }

    /// `p_b`:absorb 與後續 squeeze 用的置換(AsconXof=p12、AsconXofA=p8)。
    #[inline]
    fn pb_permute(&mut self) {
        match self.parameters {
            AsconXofParameters::AsconXof => p12(&mut self.state),
            AsconXofParameters::AsconXofA => p8(&mut self.state),
        }
    }

    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        self.pb_permute();
    }

    /// 吸收收尾:big-endian、`0x80` pad(不置換)。
    fn pad(&mut self) {
        let mut last = [0u8; RATE];
        last[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        last[self.buffer_position] = 0x80;
        self.state[0] ^= u64::from_be_bytes(last);
    }
}

impl TryDigest for AsconXof {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.parameters {
            AsconXofParameters::AsconXof => "Ascon-Xof",
            AsconXofParameters::AsconXofA => "Ascon-XofA",
        }
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        assert!(
            !self.squeezing,
            "Ascon-Xof: attempt to absorb while squeezing"
        );
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
        self.state = initial_state(self.parameters);
        self.buffer = [0; RATE];
        self.buffer_position = 0;
        self.squeezing = false;
        Ok(())
    }
}

impl TryXof for AsconXof {
    fn try_output(&mut self, mut output: &mut [u8]) -> Result<usize, Self::Error> {
        let total = output.len();

        if !self.squeezing {
            self.pad();
            self.squeezing = true;
            // 首次 squeeze 恆為完整 p12(即使 pb = p8)。
            p12(&mut self.state);
            if output.len() < RATE {
                self.buffer = self.state[0].to_be_bytes();
                let n = output.len();
                output.copy_from_slice(&self.buffer[..n]);
                self.buffer_position = n;
                return Ok(total);
            }
            output[..RATE].copy_from_slice(&self.state[0].to_be_bytes());
            output = &mut output[RATE..];
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

        // 後續整區塊:p_b 置換後寫出 S0(big-endian)。
        while output.len() >= RATE {
            self.pb_permute();
            output[..RATE].copy_from_slice(&self.state[0].to_be_bytes());
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            self.pb_permute();
            self.buffer = self.state[0].to_be_bytes();
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
    use tc_digest::{Digest, Xof};

    #[test]
    fn accessors() {
        let d = AsconXof::new(AsconXofParameters::AsconXof);
        assert_eq!(d.algorithm_name(), "Ascon-Xof");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 8);

        let a = AsconXof::new(AsconXofParameters::AsconXofA);
        assert_eq!(a.algorithm_name(), "Ascon-XofA");
    }

    // 兩變體(尤其 XofA 的 pb=8)首塊 P12、後續 pb —— 串流分段須與一次擠出相同。
    #[test]
    fn streamed_output_matches_single() {
        for p in [AsconXofParameters::AsconXof, AsconXofParameters::AsconXofA] {
            let mut a = AsconXof::new(p);
            a.update(b"the quick brown fox");
            let mut whole = [0u8; 100];
            a.output(&mut whole);

            let mut b = AsconXof::new(p);
            b.update(b"the quick brown fox");
            let mut streamed = [0u8; 100];
            let (mut off, sizes) = (0usize, [1usize, 7, 8, 9, 3, 40, 32]);
            for s in sizes {
                b.output(&mut streamed[off..off + s]);
                off += s;
            }
            assert_eq!(whole, streamed, "variant {p:?}");
        }
    }

    #[test]
    fn output_final_resets() {
        let mut a = AsconXof::new(AsconXofParameters::AsconXofA);
        a.update(b"first");
        let mut o1 = [0u8; 32];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = [0u8; 32];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }
}
