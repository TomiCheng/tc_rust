//! PHOTON-Beetle-Hash (NIST LWC), ported from Bouncy Castle's `PhotonBeetleDigest`.
//!
//! A sponge hash over the **PHOTON-256** permutation — an AES-like construction on
//! an 8×8 matrix of 4-bit nibbles over GF(2⁴), 12 rounds of AddConstant / SubCells
//! (4-bit S-box) / ShiftRows / MixColumnsSerial. The Beetle mode uses three rates:
//! a 16-byte initial block absorbed directly, a 4-byte absorption rate afterwards,
//! and a 16-byte squeeze rate for the two-block 32-byte tag. Fixed 32-byte output.

use core::convert::Infallible;

use tc_digest::TryDigest;

const DIGEST_LENGTH: usize = 32;
const STATE_BYTES: usize = 32;
const RATE: usize = 4;
const LAST_THREE_BITS_OFFSET: u8 = 5;

// 12 輪 × 8 的輪常數(展平),加在每輪第一行。
#[rustfmt::skip]
const RC: [u8; 96] = [
     1,  0,  2,  6, 14, 15, 13,  9,
     3,  2,  0,  4, 12, 13, 15, 11,
     7,  6,  4,  0,  8,  9, 11, 15,
    14, 15, 13,  9,  1,  0,  2,  6,
    13, 12, 14, 10,  2,  3,  1,  5,
    11, 10,  8, 12,  4,  5,  7,  3,
     6,  7,  5,  1,  9,  8, 10, 14,
    12, 13, 15, 11,  3,  2,  0,  4,
     9,  8, 10, 14,  6,  7,  5,  1,
     2,  3,  1,  5, 13, 12, 14, 10,
     5,  4,  6,  2, 10, 11,  9, 13,
    10, 11,  9, 13,  5,  4,  6,  2,
];

// MixColumnsSerial 的 MDS 矩陣(GF(2⁴))。
#[rustfmt::skip]
const MIX: [[u8; 8]; 8] = [
    [ 2,  4,  2, 11,  2,  8,  5,  6],
    [12,  9,  8, 13,  7,  7,  5,  2],
    [ 4,  4, 13, 13,  9,  4, 13,  9],
    [ 1,  6,  5,  1, 12, 13, 15, 14],
    [15, 12,  9, 13, 14,  5, 14, 13],
    [ 9, 14,  5, 15,  4, 12,  9,  6],
    [12,  2,  2, 10,  3,  1,  1, 14],
    [15,  1, 13, 10,  5, 10,  2,  3],
];

// 4-bit S-box。
const SBOX: [u8; 16] = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2];

/// The PHOTON-256 permutation over the 32-byte state (bc `PHOTON_Permutation`).
fn photon_permutation(state: &mut [u8; STATE_BYTES]) {
    // 拆成 8×8 nibble:nibble i 在 byte i/2 的低(i 偶)或高(i 奇)半。
    let mut s = [[0u8; 8]; 8];
    for i in 0..64 {
        s[i >> 3][i & 7] = (state[i >> 1] >> (4 * (i & 1))) & 0xf;
    }

    for round in 0..12 {
        // AddConstant:每輪第一行。
        for i in 0..8 {
            s[i][0] ^= RC[round * 8 + i];
        }
        // SubCells:每個 nibble 過 S-box。
        for row in &mut s {
            for cell in row.iter_mut() {
                *cell = SBOX[*cell as usize];
            }
        }
        // ShiftRows:第 i 列左旋 i。
        for i in 1..8 {
            let tmp = s[i];
            for j in 0..8 {
                s[i][j] = tmp[(j + i) & 7];
            }
        }
        // MixColumnsSerial:每直行乘 MDS 矩陣(GF(2⁴),多項式 x⁴+x+1)。
        let input = s;
        for (i, row) in s.iter_mut().enumerate() {
            for (j, out) in row.iter_mut().enumerate() {
                let mut sum: u32 = 0;
                for (&factor, input_row) in MIX[i].iter().zip(&input) {
                    let x = factor as u32;
                    let b = input_row[j] as u32;
                    sum ^= x * (b & 1);
                    sum ^= x * (b & 2);
                    sum ^= x * (b & 4);
                    sum ^= x * (b & 8);
                }
                // 折疊回 4-bit(兩次約簡處理進位)。
                let t0 = sum >> 4;
                sum = (sum & 15) ^ t0 ^ (t0 << 1);
                let t1 = sum >> 4;
                sum = (sum & 15) ^ t1 ^ (t1 << 1);
                *out = sum as u8;
            }
        }
    }

    // 重新打包回 32 bytes。
    for i in (0..64).step_by(2) {
        state[i >> 1] = (s[i >> 3][i & 7] & 0xf) | ((s[i >> 3][(i + 1) & 7] & 0xf) << 4);
    }
}

/// The PHOTON-Beetle-Hash digest (NIST LWC), producing a 32-byte tag.
#[derive(Clone)]
pub struct PhotonBeetleDigest {
    state: [u8; STATE_BYTES],
    buffer: [u8; 16],
    buffer_position: usize,
    /// 0 = 尚未吸收;1 = 已吸收初始 16-byte 塊;2 = 已進入 rate-4 吸收。
    phase: u8,
}

impl Default for PhotonBeetleDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl PhotonBeetleDigest {
    /// Creates a new PHOTON-Beetle-Hash digest.
    pub fn new() -> Self {
        PhotonBeetleDigest {
            state: [0; STATE_BYTES],
            buffer: [0; 16],
            buffer_position: 0,
            phase: 0,
        }
    }

    /// 處理一個滿的 16-byte 緩衝(bc `ProcessBuffer`)。
    fn process_buffer(&mut self, buf: &[u8; 16]) {
        if self.phase == 0 {
            self.state[..16].copy_from_slice(buf);
            self.phase = 1;
        } else {
            for chunk in 0..4 {
                photon_permutation(&mut self.state);
                for k in 0..RATE {
                    self.state[k] ^= buf[chunk * RATE + k];
                }
            }
            self.phase = 2;
        }
    }

    /// 吸收收尾 + domain 分離(bc `FinishAbsorbing`)。
    fn finish_absorbing(&mut self) {
        let pos = self.buffer_position;
        if self.phase == 0 {
            if pos != 0 {
                self.state[..pos].copy_from_slice(&self.buffer[..pos]);
                self.state[pos] ^= 0x01; // ozs
            }
            self.state[STATE_BYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        } else if self.phase == 1 && pos == 0 {
            self.state[STATE_BYTES - 1] ^= 2 << LAST_THREE_BITS_OFFSET;
        } else {
            let mut p = 0;
            while p + RATE <= pos {
                photon_permutation(&mut self.state);
                for k in 0..RATE {
                    self.state[k] ^= self.buffer[p + k];
                }
                p += RATE;
            }
            let remaining = pos - p;
            if remaining != 0 {
                photon_permutation(&mut self.state);
                for k in 0..remaining {
                    self.state[k] ^= self.buffer[p + k];
                }
                self.state[remaining] ^= 0x01; // ozs
                self.state[STATE_BYTES - 1] ^= 2 << LAST_THREE_BITS_OFFSET;
            } else {
                self.state[STATE_BYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
            }
        }
    }
}

impl TryDigest for PhotonBeetleDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Photon-Beetle Hash"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        // bc 未定義此值(GetByteLength 直接 throw);回傳穩態吸收 rate。
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = 16 - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == 16 {
                let block = self.buffer;
                self.process_buffer(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= 16 {
            let block: &[u8; 16] = input[..16].try_into().expect("16-byte block");
            self.process_buffer(block);
            input = &input[16..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.finish_absorbing();
        photon_permutation(&mut self.state);
        output[..16].copy_from_slice(&self.state[..16]);
        photon_permutation(&mut self.state);
        output[16..32].copy_from_slice(&self.state[..16]);
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = [0; STATE_BYTES];
        self.buffer = [0; 16];
        self.buffer_position = 0;
        self.phase = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(input: &[u8]) -> String {
        let mut d = PhotonBeetleDigest::new();
        d.update(input);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn accessors() {
        let d = PhotonBeetleDigest::new();
        assert_eq!(d.algorithm_name(), "Photon-Beetle Hash");
        assert_eq!(d.digest_size(), 32);
    }

    // 官方 KAT 的代表性向量(訊息為 00,01,…,長度 0/16/17/20/32),涵蓋
    // phase 0/1/2 與 domain 分離。完整 1025 條見 tests/photon_beetle_kat.rs。
    #[test]
    fn known_vectors() {
        let cases: [(usize, &str); 5] = [
            (
                0,
                "44a99882fea033566856a27e7f0c94dc84fac7e411b08b890a4a574e3db75d4a",
            ),
            (
                16,
                "ab0d1eb0315df8af7f7ae0ac42eaf2f52fb0fdf0904e182dcc796b6cb8d7981a",
            ),
            (
                17,
                "5a281ad7eb81fb083d05ccd21b78c4bca938af26f20869da29c8f13b7389bc5f",
            ),
            (
                20,
                "e6470f7fb66345b3db97774832ab07f26dd836b6cd3b28afa74f67404368f54f",
            ),
            (
                32,
                "73609f6a67b96085829dfe8a3fe3ebc767f48a493640dd97461957ad995239e5",
            ),
        ];
        for (len, expected) in cases {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(hex(&msg), expected, "length {len}");
        }
    }

    // 分段餵與一次餵應相同(跨初始 16 / rate 4 邊界)。
    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let whole = hex(&msg);

        let mut d = PhotonBeetleDigest::new();
        for c in msg.chunks(5) {
            d.update(c);
        }
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(s, whole);
    }
}
