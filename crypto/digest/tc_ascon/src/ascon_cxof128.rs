//! Ascon-CXOF128 from NIST SP 800-232, ported from Bouncy Castle's `AsconCXof128`.
//!
//! A customizable extendable-output function (XOF) over the Ascon-p\[12]
//! permutation with an 8-byte rate. This is the crate's first user of the
//! [`tc_digest::TryXof`] / [`tc_digest::Xof`] traits, so it
//! doubles as a fitness check on that API.

use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;
const MAX_CUSTOMIZATION: usize = 256;

// 空 customization 的預算初始狀態(bc 快取值)。
const IV_EMPTY: [u64; 5] = [
    0x500c_ccc8_94e3_c9e8,
    0x5bed_06f2_8f71_248d,
    0x3b03_a0f9_30af_d512,
    0x112e_f093_aa5c_698b,
    0x00c8_3563_40a3_47f0,
];

// 非空 customization 起始 IV(吸收 z 前)。
const IV_CUSTOM: [u64; 5] = [
    0x6755_27c2_a0e8_de03,
    0x43d1_2d7d_c037_7bbc,
    0xe990_1dec_426e_81b5,
    0x2ab1_4907_7207_80b6,
    0x8f3f_1d02_d432_bc46,
];

/// The customizable 256-bit Ascon XOF (Ascon-CXOF128) from NIST SP 800-232.
#[derive(Clone)]
pub struct AsconCXof128 {
    state: [u64; 5],
    /// 吸收完 customization 後的狀態,`reset` 時還原。
    initial: [u64; 5],
    /// 吸收階段為輸入緩衝;擠出階段為當前輸出區塊。
    buffer: [u8; RATE],
    /// 吸收階段 = buffer 已填位元組;擠出階段 = 當前輸出區塊已消耗位元組(8 = 需再置換)。
    buffer_position: usize,
    squeezing: bool,
}

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconCXof128 {
    /// Creates an Ascon-CXOF128 with an empty customization string.
    pub fn new() -> Self {
        AsconCXof128 {
            state: IV_EMPTY,
            initial: IV_EMPTY,
            buffer: [0; RATE],
            buffer_position: 0,
            squeezing: false,
        }
    }

    /// Creates an Ascon-CXOF128 with the given customization string `z`.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentOutOfRangeException`) if `z` is longer than
    /// 256 bytes.
    pub fn with_customization(z: &[u8]) -> Self {
        assert!(
            z.len() <= MAX_CUSTOMIZATION,
            "Ascon-CXOF128: customization string too long (max 256 bytes)"
        );

        let state = if z.is_empty() {
            IV_EMPTY
        } else {
            let mut state = IV_CUSTOM;
            state[0] ^= (z.len() as u64) << 3;
            p12(&mut state);

            let mut chunks = z.chunks_exact(RATE);
            for block in chunks.by_ref() {
                state[0] ^= u64::from_le_bytes(block.try_into().unwrap());
                p12(&mut state);
            }
            let rem = chunks.remainder();
            let mut last = [0u8; RATE];
            last[..rem.len()].copy_from_slice(rem);
            last[rem.len()] = 0x01;
            state[0] ^= u64::from_le_bytes(last);
            p12(&mut state);

            state
        };

        AsconCXof128 {
            state,
            initial: state,
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

    /// 吸收收尾:把殘留緩衝 + `0x01` pad XOR 進 S0(不置換 —— 由呼叫端後續處理)。
    fn pad(&mut self) {
        let mut last = [0u8; RATE];
        last[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        last[self.buffer_position] = 0x01;
        self.state[0] ^= u64::from_le_bytes(last);
    }
}

impl TryDigest for AsconCXof128 {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Ascon-CXOF128"
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
            "Ascon-CXOF128: attempt to absorb while squeezing"
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
        self.state = self.initial;
        self.buffer = [0; RATE];
        self.buffer_position = 0;
        self.squeezing = false;
        Ok(())
    }
}

impl TryXof for AsconCXof128 {
    fn try_output(&mut self, mut output: &mut [u8]) -> Result<usize, Self::Error> {
        let total = output.len();

        if !self.squeezing {
            // 收尾吸收後進入擠出;buffer_position = RATE 表示尚無已擠出的區塊。
            self.pad();
            self.squeezing = true;
            self.buffer_position = RATE;
        } else if self.buffer_position < RATE {
            // 先把上一個輸出區塊的剩餘位元組排出。
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

        // 整區塊:置換後直接寫出 S0。
        while output.len() >= RATE {
            p12(&mut self.state);
            output[..RATE].copy_from_slice(&self.state[0].to_le_bytes());
            output = &mut output[RATE..];
        }

        // 尾段:置換一次、緩衝一個區塊、寫出所需並記錄消耗量。
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
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_digest::{Digest, Xof};

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 一次擠出 N bytes 與分段擠出應完全相同(串流連續性)。
    #[test]
    fn streamed_output_matches_single() {
        let mut a = AsconCXof128::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 100];
        a.output(&mut whole);

        let mut b = AsconCXof128::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 100];
        // 以不對齊 rate 的切段擠出。
        let (mut off, sizes) = (0usize, [1usize, 7, 8, 9, 3, 40, 32]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        assert_eq!(whole, streamed);
    }

    // output_final 擠出後應 reset,可立即吸收新訊息。
    #[test]
    fn output_final_resets() {
        let mut a = AsconCXof128::new();
        a.update(b"first");
        let mut o1 = [0u8; 32];
        a.output_final(&mut o1);
        // reset 後重算應與全新實例相同。
        a.update(b"first");
        let mut o2 = [0u8; 32];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }

    // do_final(Digest 介面)= 32-byte output_final。
    #[test]
    fn do_final_is_32_byte_output_final() {
        let mut a = AsconCXof128::new();
        a.update(b"abc");
        let mut viafinal = [0u8; 32];
        a.do_final(&mut viafinal);

        let mut b = AsconCXof128::new();
        b.update(b"abc");
        let mut viaxof = [0u8; 32];
        b.output_final(&mut viaxof);
        assert_eq!(viafinal, viaxof);
    }

    // customization string 應改變輸出。
    #[test]
    fn customization_changes_output() {
        let mut a = AsconCXof128::new();
        a.update(b"msg");
        let mut oa = [0u8; 32];
        a.output_final(&mut oa);

        let mut b = AsconCXof128::with_customization(b"ctx");
        b.update(b"msg");
        let mut ob = [0u8; 32];
        b.output_final(&mut ob);
        assert_ne!(oa, ob);
    }

    #[test]
    fn accessors() {
        let d = AsconCXof128::new();
        assert_eq!(d.algorithm_name(), "Ascon-CXOF128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 8);
    }

    // 自洽驗證:空 customization = 非空路徑套用 z=empty,即
    //   IV_CUSTOM → P12 → pad(S0 ^= 0x01) → P12 == IV_EMPTY。
    // 這驗證兩個 IV 常數彼此一致,且與 `with_customization` 的吸收/pad/置換邏輯
    // 及 P12 對上 NIST SP 800-232 的初始化。
    #[test]
    fn init_constants_match_ascon_derivation() {
        let mut s = IV_CUSTOM;
        p12(&mut s); // S0 ^= (0 << 3) 為 no-op
        s[0] ^= 0x01; // PadAndAbsorb,空緩衝
        p12(&mut s);
        assert_eq!(s, IV_EMPTY);
    }

    // 分段吸收與一次吸收相同。
    #[test]
    fn chunked_absorb_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = AsconCXof128::new();
        a.update(&msg);
        let mut oa = vec![0u8; 48];
        a.output_final(&mut oa);

        let mut b = AsconCXof128::new();
        for c in msg.chunks(5) {
            b.update(c);
        }
        let mut ob = vec![0u8; 48];
        b.output_final(&mut ob);
        assert_eq!(oa, ob);
        let _ = hex(&oa);
    }
}
