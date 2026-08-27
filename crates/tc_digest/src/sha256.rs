//! SHA-256 message digest (FIPS 180-2), ported from Bouncy Castle's `Sha256Digest`.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha256_core::compress;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 64;

// 初始鏈結值:前 8 個質數平方根小數部分的前 32 bit。
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The SHA-256 digest (FIPS 180-2), producing a 32-byte hash.
#[derive(Clone)]
pub struct Sha256Digest {
    /// 8 個鏈結暫存器 H1..H8。
    h: [u32; 8],
    /// 共用的 64-byte 區塊緩衝。
    buf: MdBuffer<64>,
}

impl Default for Sha256Digest {
    fn default() -> Self {
        Sha256Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl Sha256Digest {
    /// Creates a fresh SHA-256 digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for Sha256Digest {
    type Error = Infallible; // 純計算,永不失敗 → 自動獲得 Digest

    fn algorithm_name(&self) -> &str {
        "SHA-256"
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
            // SHA-256 長度欄位為 big-endian 64-bit 位元長度。
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            for (i, &word) in h.iter().enumerate() {
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
    use tc_crypto_core::Digest;

    fn sha256_hex(input: &[u8]) -> String {
        let mut d = Sha256Digest::new();
        d.update(input);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // FIPS 180-2 的知名測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"message digest"),
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        );
        assert_eq!(
            sha256_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
        );
        // 56-byte 訊息:跨越 padding 需第二塊的邊界。
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha256Digest::new();
        assert_eq!(d.algorithm_name(), "SHA-256");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha256Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        d.do_final(&mut out); // 應得空字串摘要
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            s,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Sha256Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 32];
        a.do_final(&mut oa);

        let mut b = Sha256Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..64]);
        b.update(&msg[64..130]);
        b.update(&msg[130..]);
        let mut ob = [0u8; 32];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
