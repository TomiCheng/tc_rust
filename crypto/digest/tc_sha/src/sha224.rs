//! SHA-224 message digest (FIPS 180-2), ported from Bouncy Castle's `Sha224Digest`.
//!
//! SHA-224 is SHA-256 with a different IV and a truncated (28-byte) output — it
//! reuses the shared private `sha256_core::compress` function
//! verbatim.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha256_core::compress;

const DIGEST_LENGTH: usize = 28;
const BYTE_LENGTH: usize = 64;

// 初始鏈結值(FIPS 180-4;第 9..16 個質數平方根的前 32 bit)。
const IV: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// The SHA-224 digest (FIPS 180-2), producing a 28-byte hash.
#[derive(Clone)]
pub struct Sha224Digest {
    /// 8 個鏈結暫存器(輸出只取前 7 個)。
    h: [u32; 8],
    /// 共用的 64-byte 區塊緩衝。
    buf: MdBuffer<64>,
}

impl Default for Sha224Digest {
    fn default() -> Self {
        Sha224Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl Sha224Digest {
    /// Creates a fresh SHA-224 digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for Sha224Digest {
    type Error = Infallible; // 純計算,永不失敗 → 自動獲得 Digest

    fn algorithm_name(&self) -> &str {
        "SHA-224"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| compress(h, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { h, buf } = self;
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            // 只輸出前 7 個暫存器(28 bytes),丟棄 H8。
            for (i, &word) in h.iter().take(7).enumerate() {
                output[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
        }
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.h = IV;
        self.buf.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn sha224_hex(input: &[u8]) -> String {
        let mut d = Sha224Digest::new();
        d.update(input);
        let mut out = [0u8; 28];
        d.do_final(&mut out);
        let mut s = String::with_capacity(56);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // FIPS 180-2 的知名測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha224_hex(b""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            sha224_hex(b"abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        // 56-byte 訊息:跨越 padding 需第二塊的邊界。
        assert_eq!(
            sha224_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha224Digest::new();
        assert_eq!(d.algorithm_name(), "SHA-224");
        assert_eq!(d.digest_size(), 28);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha224Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 28];
        d.do_final(&mut out);
        d.do_final(&mut out); // 應得空字串摘要
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            s,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Sha224Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 28];
        a.do_final(&mut oa);

        let mut b = Sha224Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 28];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
