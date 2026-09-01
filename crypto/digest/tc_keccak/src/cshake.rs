//! cSHAKE — customizable SHAKE (NIST SP 800-185), ported from Bouncy Castle's
//! `CShakeDigest`.
//!
//! cSHAKE parameterizes SHAKE with a NIST function-name string `N` and a caller
//! customization string `S`. When both are empty it is *exactly* SHAKE (domain
//! `0x1f`); otherwise the sponge first absorbs
//! `bytepad(encode_string(N) || encode_string(S), rate)` and switches the domain
//! pad to `0x04` (the `00` two-bit cSHAKE suffix + `pad10*1`).
//!
//! `bytepad` / `left_encode` / `encode_string` follow SP 800-185 §2.3 and reuse
//! the [`KeccakDigest`] sponge (with its `xof_output` incremental squeeze).

use alloc::vec::Vec;
use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};

use crate::keccak::KeccakDigest;
use crate::xof_utils::{encode_string, left_encode};

/// A cSHAKE128 / cSHAKE256 customizable XOF (SP 800-185).
#[derive(Clone)]
pub struct CShakeDigest {
    sponge: KeccakDigest,
    /// 安全參數位元數(128 或 256),決定名稱與預設輸出長度。
    bit_length: usize,
    /// bytepad 前綴;`None` 表示 N/S 皆空 → 退化為純 SHAKE。
    diff: Option<Vec<u8>>,
}

impl CShakeDigest {
    /// Creates cSHAKE-`bit_length` with function name `n` and customization `s`.
    ///
    /// `bit_length` must be 128 or 256. `n` is reserved for NIST use (pass an
    /// empty slice unless a standard mandates it). Both empty ⇒ plain SHAKE.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentException`) for an unsupported parameter.
    pub fn new(bit_length: usize, n: &[u8], s: &[u8]) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "cSHAKE: bit length must be 128 or 256"
        );

        if n.is_empty() && s.is_empty() {
            // N/S 皆空:與 SHAKE 完全相同(domain 0x1f)。
            return CShakeDigest {
                sponge: KeccakDigest::with_domain(bit_length, 0x1f, "CSHAKE"),
                bit_length,
                diff: None,
            };
        }

        let rate_bytes = (1600 - (bit_length << 1)) / 8;
        let mut diff = left_encode(rate_bytes as u64);
        diff.extend(encode_string(n));
        diff.extend(encode_string(s));

        let mut d = CShakeDigest {
            sponge: KeccakDigest::with_domain(bit_length, 0x04, "CSHAKE"),
            bit_length,
            diff: Some(diff),
        };
        d.diff_pad_and_absorb();
        d
    }

    /// SP 800-185 `bytepad`:吸收 `diff`,再補零至 rate 的整數倍(令訊息從區塊邊界開始)。
    fn diff_pad_and_absorb(&mut self) {
        // 分別借用 sponge / diff 兩個欄位(避免整體 &self 與 &mut self 衝突)。
        let Self { sponge, diff, .. } = self;
        let Some(diff) = diff.as_ref() else {
            return;
        };
        let block_size = sponge.byte_length();
        let _ = sponge.try_update(diff);

        let delta = diff.len() % block_size;
        if delta != 0 {
            // pad < block_size ≤ 168,單次補零即足。
            let zeros = [0u8; 168];
            let _ = sponge.try_update(&zeros[..block_size - delta]);
        }
    }
}

impl TryDigest for CShakeDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.bit_length {
            128 => "CSHAKE128",
            _ => "CSHAKE256",
        }
    }

    fn digest_size(&self) -> usize {
        // 同 SHAKE:安全參數的兩倍位元組(128→32、256→64)。
        self.bit_length / 4
    }

    fn byte_length(&self) -> usize {
        self.sponge.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.sponge.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_size();
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.sponge.try_reset()?;
        // 自訂化時 reset 需重新注入 bytepad 前綴。
        self.diff_pad_and_absorb();
        Ok(())
    }
}

impl TryXof for CShakeDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // domain(0x04 自訂 / 0x1f 退化 SHAKE)已烘進 sponge,直接續擠。
        self.sponge.xof_output(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use tc_digest::{Digest, Xof};

    fn unhex(s: &str) -> Vec<u8> {
        let d: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        d.chunks(2)
            .map(|p| (p[0].to_digit(16).unwrap() as u8) << 4 | p[1].to_digit(16).unwrap() as u8)
            .collect()
    }

    #[test]
    fn accessors() {
        let d = CShakeDigest::new(128, b"", b"Email Signature");
        assert_eq!(d.algorithm_name(), "CSHAKE128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 168);

        let d = CShakeDigest::new(256, b"", b"Email Signature");
        assert_eq!(d.algorithm_name(), "CSHAKE256");
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 136);
    }

    // NIST SP 800-185 cSHAKE 官方樣本 #1-#4(N 空、S = "Email Signature")。
    #[test]
    fn nist_samples() {
        // cSHAKE128 / 4-byte message。
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5")
        );

        // cSHAKE128 / 1600-bit message(0x00..0xC7)。
        let msg: Vec<u8> = (0u16..200).map(|i| i as u8).collect();
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&msg);
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b")
        );

        // cSHAKE256 / 4-byte message。
        let mut d = CShakeDigest::new(256, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 64];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1\
                 64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"
            )
        );

        // cSHAKE256 / 1600-bit message。
        let mut d = CShakeDigest::new(256, b"", b"Email Signature");
        d.update(&msg);
        let mut o = [0u8; 64];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917\
                 27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb"
            )
        );
    }

    // bc checkZeroPadZ:大型 S 導致多區塊 bytepad(含 N 非空的一例)。
    #[test]
    fn zero_pad_z() {
        let mut d = CShakeDigest::new(256, b"", &[0u8; 265]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("6e393540387004f087c4180db008acf6825190cf")
        );

        let mut d = CShakeDigest::new(128, b"", &[0u8; 329]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("309bd7c285fcf8b839c9686b2cc00bd578947bee")
        );

        let mut d = CShakeDigest::new(128, &[0u8; 29], &[0u8; 300]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("ff6aafd83b8d22fc3e2e9b9948b581967ed9c5e7")
        );
    }

    // N/S 皆空時應與純 SHAKE 完全相同。
    #[test]
    fn empty_customization_equals_shake() {
        use crate::shake::ShakeDigest;
        let msg = unhex("eeaabeef");
        for bits in [128usize, 256] {
            let mut r = ShakeDigest::new(bits);
            r.update(&msg);
            let mut ro = [0u8; 32];
            r.output_final(&mut ro);

            let mut c = CShakeDigest::new(bits, b"", b"");
            c.update(&msg);
            let mut co = [0u8; 32];
            c.output_final(&mut co);
            assert_eq!(ro, co, "cSHAKE{bits}(empty) must equal SHAKE{bits}");
        }
    }

    // bc doFinalTest:output 續擠不重置,output_final 收尾並重置。
    #[test]
    fn output_vs_output_final_reset() {
        let first = unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(o.to_vec(), first);
        // 續擠:下一段輸出不同(同一擠出流的後續位元組)。
        d.output(&mut o);
        assert_ne!(o.to_vec(), first);

        // output_final 後重置,重算同一輸入回到起點。
        d.output_final(&mut o);
        d.update(&unhex("00010203"));
        d.output_final(&mut o);
        assert_eq!(o.to_vec(), first);
    }

    #[test]
    fn long_block() {
        let data: Vec<u8> = (0u32..200).map(|i| i as u8).collect();
        let mut d = CShakeDigest::new(256, b"", &[0u8; 200]);
        d.update(&data);
        let mut o = vec![0u8; 32];
        d.output_final(&mut o);
        assert_eq!(
            o,
            unhex("4a899b5be460d85a9789215bc17f88b8f8ac049bd3b519f561e7b5d3870dafa3")
        );
    }
}
