//! MD2 message digest (RFC 1319), ported from Bouncy Castle's `MD2Digest`.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

const DIGEST_LENGTH: usize = 16;
const BYTE_LENGTH: usize = 16;

/// The MD2 digest (RFC 1319), producing a 16-byte hash.
///
/// MD2 is cryptographically broken and kept only for interoperability with
/// legacy data; do not use it for new designs.
#[derive(Clone)]
pub struct Md2Digest {
    /// X 緩衝：48 bytes 的內部狀態。
    x: [u8; 48],
    /// M 緩衝：累積中的當前 16-byte 區塊。
    m: [u8; 16],
    /// M 中已填入的位元組數（0..16）。
    m_off: usize,
    /// C 緩衝：16-byte 校驗和。
    c: [u8; 16],
}

impl Default for Md2Digest {
    fn default() -> Self {
        Md2Digest {
            x: [0; 48],
            m: [0; 16],
            m_off: 0,
            c: [0; 16],
        }
    }
}

impl Md2Digest {
    /// Creates a fresh MD2 digest.
    pub fn new() -> Self {
        Self::default()
    }

    /// 吃進單一位元組（bc `Update`）；填滿 16-byte 區塊就處理並清空。
    fn process_byte(&mut self, input: u8) {
        self.m[self.m_off] = input;
        self.m_off += 1;
        if self.m_off == 16 {
            let m = self.m;
            self.process_checksum(m);
            self.process_block(m);
            self.m_off = 0;
        }
    }

    /// 更新校驗和 C（bc `ProcessChecksum`）。`m` 傳值以避開對 `self` 的借用衝突。
    fn process_checksum(&mut self, m: [u8; 16]) {
        let mut l = self.c[15];
        for i in 0..16 {
            self.c[i] ^= S[(m[i] ^ l) as usize];
            l = self.c[i];
        }
    }

    /// 壓縮一個區塊進 X（bc `ProcessBlock`）。`m` 可能是 M 或 C,故傳值。
    fn process_block(&mut self, m: [u8; 16]) {
        for i in 0..16 {
            self.x[i + 16] = m[i];
            self.x[i + 32] = m[i] ^ self.x[i];
        }
        // 18 輪擴散;t 為 u8 → 遮罩到 0xff 是天然的。
        let mut t: u8 = 0;
        for j in 0..18u8 {
            for k in 0..48 {
                self.x[k] ^= S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j); // (t + j) mod 256
        }
    }

    /// 歸零全部狀態。
    fn reset_state(&mut self) {
        self.x = [0; 48];
        self.m = [0; 16];
        self.m_off = 0;
        self.c = [0; 16];
    }
}

impl TryDigest for Md2Digest {
    type Error = Infallible; // 純計算,永不失敗 → 自動獲得 Digest

    fn algorithm_name(&self) -> &str {
        "MD2"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // 逐位元組處理。bc 對整區塊有 16-byte 快複製優化,結果與逐位元組完全相同。
        for &b in input {
            self.process_byte(b);
        }
        Ok(())
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.process_byte(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // 補齊 padding：每個補位的值 = 缺的位元組數。
        let padding = (16 - self.m_off) as u8;
        for i in self.m_off..16 {
            self.m[i] = padding;
        }
        // 最後一塊的校驗和 → 處理最後訊息塊 → 再處理校驗和塊。
        let m = self.m;
        self.process_checksum(m);
        self.process_block(m);
        let c = self.c; // 須在 process_checksum 之後取,才含最後一塊的校驗和
        self.process_block(c);

        output[..16].copy_from_slice(&self.x[..16]);

        self.reset_state();
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.reset_state();
        Ok(())
    }
}

/// 256-byte S-box：由圓周率 π 的位數構成的隨機置換(RFC 1319)。逐列對齊 bc `MD2Digest.S`。
#[rustfmt::skip]
static S: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124,
    1, 61, 54, 84, 161, 236, 240,
    6, 19, 98, 167, 5, 243, 192,
    199, 115, 140, 152, 147, 43, 217,
    188, 76, 130, 202, 30, 155, 87,
    60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190,
    78, 196, 214, 218, 158, 222, 73,
    160, 251, 245, 142, 187, 47, 238,
    122, 169, 104, 121, 145, 21, 178,
    7, 63, 148, 194, 16, 137, 11,
    34, 95, 33, 128, 127, 93, 154,
    90, 144, 50, 39, 53, 62, 204,
    231, 191, 247, 151, 3, 255, 25,
    48, 179, 72, 165, 181, 209, 215,
    94, 146, 42, 172, 86, 170, 198,
    79, 184, 56, 210, 150, 164, 125,
    182, 118, 252, 107, 226, 156, 116,
    4, 241, 69, 157, 112, 89, 100,
    113, 135, 32, 134, 91, 207, 101,
    230, 45, 168, 2, 27, 96, 37,
    173, 174, 176, 185, 246, 28, 70,
    97, 105, 52, 64, 126, 15, 85,
    71, 163, 35, 221, 81, 175, 58,
    195, 92, 249, 206, 186, 197, 234,
    38, 44, 83, 13, 110, 133, 40,
    132, 9, 211, 223, 205, 244, 65,
    129, 77, 82, 106, 220, 55, 200,
    108, 193, 171, 250, 36, 225, 123,
    8, 12, 189, 177, 74, 120, 136,
    149, 139, 227, 99, 232, 109, 233,
    203, 213, 254, 59, 0, 29, 57,
    242, 239, 183, 14, 102, 88, 208,
    228, 166, 119, 114, 248, 235, 117,
    75, 10, 49, 68, 80, 180, 143,
    237, 31, 26, 219, 153, 141, 51,
    159, 17, 131, 20,
];

#[cfg(test)]
mod tests {
    use super::*;
    use tc_crypto_core::Digest;

    /// 便利：對輸入求 MD2,回傳 16-byte 摘要的十六進位字串。
    /// 測試模式下為 std,`String`/`format!` 由 prelude 提供。
    fn hex16(out: [u8; 16]) -> String {
        let mut s = String::with_capacity(32);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn md2_hex(input: &[u8]) -> String {
        let mut d = Md2Digest::new();
        d.update(input);
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        hex16(out)
    }

    // RFC 1319 附錄 A.5 的官方測試向量。
    #[test]
    fn rfc1319_vectors() {
        assert_eq!(md2_hex(b""), "8350e5a3e24c153df2275c9f80692773");
        assert_eq!(md2_hex(b"a"), "32ec01ec4a6dac72c0ab96fb34c0b5d1");
        assert_eq!(md2_hex(b"abc"), "da853b0d3f88d99b30283a69e6ded6bb");
        assert_eq!(md2_hex(b"message digest"), "ab4f496bfb2a530b219ff33031fe06b0");
        assert_eq!(
            md2_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "4e8ddff3650292ab5a4108c3aa47940b"
        );
    }

    #[test]
    fn accessors() {
        let d = Md2Digest::new();
        assert_eq!(d.algorithm_name(), "MD2");
        assert_eq!(d.digest_size(), 16);
        assert_eq!(d.byte_length(), 16);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Md2Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        // 再算一次空字串,應得空字串的摘要(證明已 reset)。
        d.do_final(&mut out);
        assert_eq!(hex16(out), "8350e5a3e24c153df2275c9f80692773");
    }

    #[test]
    fn byte_by_byte_matches_bulk() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut a = Md2Digest::new();
        a.update(msg);
        let mut oa = [0u8; 16];
        a.do_final(&mut oa);

        let mut b = Md2Digest::new();
        for &byte in msg {
            b.update_byte(byte);
        }
        let mut ob = [0u8; 16];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
