//! SHA-384 message digest (FIPS 180-2), ported from Bouncy Castle's `Sha384Digest`.
//!
//! SHA-384 is SHA-512 with a different IV and a truncated (48-byte) output — it
//! reuses the shared [`sha512_core::compress`](crate::sha512_core::compress)
//! verbatim.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha512_core::compress;

const DIGEST_LENGTH: usize = 48;
const BYTE_LENGTH: usize = 128;

// 初始鏈結值(FIPS 180-4;第 9..16 個質數平方根的前 64 bit)。
const IV: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// The SHA-384 digest (FIPS 180-2), producing a 48-byte hash.
#[derive(Clone)]
pub struct Sha384Digest {
    /// 8 個 64-bit 鏈結暫存器(輸出只取前 6 個)。
    h: [u64; 8],
    /// 共用的 128-byte 區塊緩衝。
    buf: MdBuffer<128>,
}

impl Default for Sha384Digest {
    fn default() -> Self {
        Sha384Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl Sha384Digest {
    /// Creates a fresh SHA-384 digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for Sha384Digest {
    type Error = Infallible; // 純計算,永不失敗 → 自動獲得 Digest

    fn algorithm_name(&self) -> &str {
        "SHA-384"
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
            let bit_len = (buf.byte_count() as u128) << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            // 只輸出前 6 個暫存器(48 bytes),丟棄 H7、H8。
            for (i, &word) in h.iter().take(6).enumerate() {
                output[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
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

    fn sha384_hex(input: &[u8]) -> String {
        let mut d = Sha384Digest::new();
        d.update(input);
        let mut out = [0u8; 48];
        d.do_final(&mut out);
        let mut s = String::with_capacity(96);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // FIPS 180-2 的知名測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha384_hex(b""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
             4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            sha384_hex(b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        // 112-byte 訊息:跨越 padding 需第二塊的邊界。
        assert_eq!(
            sha384_hex(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2\
             2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha384Digest::new();
        assert_eq!(d.algorithm_name(), "SHA-384");
        assert_eq!(d.digest_size(), 48);
        assert_eq!(d.byte_length(), 128);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha384Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 48];
        d.do_final(&mut out);
        d.do_final(&mut out); // 應得空字串摘要
        assert_eq!(
            {
                let mut s = String::new();
                for b in out {
                    s.push_str(&format!("{b:02x}"));
                }
                s
            },
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
             4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let mut a = Sha384Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 48];
        a.do_final(&mut oa);

        let mut b = Sha384Digest::new();
        b.update(&msg[..128]);
        b.update(&msg[128..]);
        let mut ob = [0u8; 48];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
