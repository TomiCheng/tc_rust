//! Block-cipher trait, ported from Bouncy Castle's `IBlockCipher`.
//!
//! Following this crate's charter, `tc_crypto_core` ships only the *contract*:
//! the parameter type and the error type are **associated types** supplied by
//! the implementor, exactly as `rand_core`'s `SeedableRng` leaves `Seed` to the
//! concrete RNG. So core names no concrete parameter struct, no key type, and no
//! error enum — a `KeyParameter`, `TweakableBlockCipherParameters`, and friends
//! live in whichever crate implements the cipher.
//!
//! Unlike [`TryDigest`](crate::TryDigest) / [`Digest`](crate::Digest), there is no
//! fallible/infallible split here: a block cipher's [`init`](BlockCipher::init)
//! validates its key and parameters and can genuinely fail even in pure software,
//! so there is no useful "infallible block cipher" to hand a `Result`-free API.
//! The single trait therefore returns `Result` from its data methods.

/// A symmetric-key block cipher (bc `IBlockCipher`).
///
/// Initialise once with [`init`](BlockCipher::init), then transform data one
/// block at a time with [`process_block`](BlockCipher::process_block). The
/// engine retains its key schedule between blocks; each `process_block` call is
/// independent (the raw ECB primitive — chaining modes wrap this).
pub trait BlockCipher {
    /// The parameter accepted by [`init`](BlockCipher::init) — bc's
    /// `ICipherParameters`, made concrete per implementor.
    ///
    /// A generic associated type so that a *borrowing* parameter (e.g. one that
    /// holds `&'a [u8]` key material) receives a fresh lifetime on every call,
    /// tied only to that call's arguments.
    type Params<'a>;

    /// The failure type; e.g. an invalid key length or an output buffer too
    /// short. Use [`Infallible`](core::convert::Infallible) only if construction
    /// and processing truly cannot fail.
    type Error: core::error::Error;

    /// The algorithm name (bc `AlgorithmName`), e.g. `"Threefish-256"`.
    fn algorithm_name(&self) -> &str;

    /// The block size in bytes (bc `GetBlockSize`).
    fn block_size(&self) -> usize;

    /// Initialises the cipher for encryption (`for_encryption = true`) or
    /// decryption (`for_encryption = false`) with the given parameters
    /// (bc `Init`).
    ///
    /// The parameters are taken **by reference**: `init` does not consume them,
    /// so one parameter value — however expensive to build, e.g. a validated set
    /// of shared domain parameters used by many keys — can be constructed once
    /// and handed to any number of `init` calls.
    ///
    /// Fails if the parameters are unsuitable (wrong key length, missing key,
    /// unsupported parameter shape).
    fn init(
        &mut self,
        for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;

    /// Processes exactly one block from `input` into `output`, returning the
    /// number of bytes produced — always [`block_size`](BlockCipher::block_size)
    /// (bc `ProcessBlock`).
    ///
    /// For a partial buffer or an offset, slice at the call site. Fails if
    /// `input` is shorter than one block, `output` cannot hold one block, or the
    /// cipher was never initialised.
    fn process_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt;

    // 兩個玩具 "cipher",8-byte 分組,每位元組 XOR 一個 pad。目的只在驗證
    // trait 形狀:GAT + by-ref 讓 param 既能「借用」也能「擁有並共享」。

    #[derive(Debug, PartialEq)]
    enum ToyError {
        NoKey,
        BufferTooShort,
    }

    impl fmt::Display for ToyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ToyError::NoKey => write!(f, "cipher not initialised"),
                ToyError::BufferTooShort => write!(f, "buffer too short"),
            }
        }
    }

    impl core::error::Error for ToyError {}

    fn xor8(pad: u8, input: &[u8], output: &mut [u8]) -> Result<usize, ToyError> {
        if input.len() < 8 || output.len() < 8 {
            return Err(ToyError::BufferTooShort);
        }
        for i in 0..8 {
            output[i] = input[i] ^ pad;
        }
        Ok(8)
    }

    // ---- 情境一:借用式 param(帶 &'a [u8],GAT 的 'a 真的被用到)----

    struct BorrowKey<'a> {
        key: &'a [u8],
    }

    struct BorrowCipher {
        pad: Option<u8>,
    }

    impl BlockCipher for BorrowCipher {
        type Params<'a> = BorrowKey<'a>;
        type Error = ToyError;

        fn algorithm_name(&self) -> &str {
            "Borrow-64"
        }
        fn block_size(&self) -> usize {
            8
        }
        fn init(&mut self, _enc: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
            self.pad = Some(*params.key.first().ok_or(ToyError::NoKey)?);
            Ok(())
        }
        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            xor8(self.pad.ok_or(ToyError::NoKey)?, input, output)
        }
    }

    // ---- 情境二:擁有式 param,lifetime-free,by-ref 讓多個實例共用同一份 ----
    // 模擬「建構昂貴、多把 key 共用的 domain 參數」(如 DHParameters)。
    // GAT 的 'a 在這裡忽略不用 —— 同一個 trait 兩種 param 都容得下。

    struct SharedConfig {
        pad: u8,
        // 想像這裡還有一大包驗證過的欄位,建構代價很高。
    }

    struct OwnCipher {
        pad: Option<u8>,
    }

    impl BlockCipher for OwnCipher {
        type Params<'a> = SharedConfig;
        type Error = ToyError;

        fn algorithm_name(&self) -> &str {
            "Own-64"
        }
        fn block_size(&self) -> usize {
            8
        }
        fn init(&mut self, _enc: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
            self.pad = Some(params.pad);
            Ok(())
        }
        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            xor8(self.pad.ok_or(ToyError::NoKey)?, input, output)
        }
    }

    #[test]
    fn borrowing_param_roundtrips_and_is_reusable() {
        let mut c = BorrowCipher { pad: None };
        let key = [0xFFu8];
        let params = BorrowKey { key: &key };

        // by-ref:同一份 params 連續 init 兩次,沒有被消耗。
        c.init(true, &params).unwrap();
        c.init(false, &params).unwrap();

        let input = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut ct = [0u8; 8];
        let mut pt = [0u8; 8];
        c.process_block(&input, &mut ct).unwrap();
        c.process_block(&ct, &mut pt).unwrap();
        assert_eq!(pt, input); // XOR 0xFF 兩次還原
    }

    #[test]
    fn owned_param_is_built_once_and_shared_by_reference() {
        // 建構一次(昂貴),多個 cipher 實例共用同一份參考。
        let cfg = SharedConfig { pad: 0xA5 };

        let mut a = OwnCipher { pad: None };
        let mut b = OwnCipher { pad: None };
        a.init(true, &cfg).unwrap(); // 借
        b.init(true, &cfg).unwrap(); // 再借,cfg 仍在

        let input = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (mut oa, mut ob) = ([0u8; 8], [0u8; 8]);
        a.process_block(&input, &mut oa).unwrap();
        b.process_block(&input, &mut ob).unwrap();
        assert_eq!(oa, ob); // 兩者共用同參數 → 同結果
        // cfg 用完仍可再用,證明沒被 move。
        assert_eq!(cfg.pad, 0xA5);
    }

    #[test]
    fn errors_before_init_and_on_short_buffer() {
        let mut c = BorrowCipher { pad: None };
        let mut out = [0u8; 8];
        assert_eq!(c.process_block(&[0u8; 8], &mut out), Err(ToyError::NoKey));

        c.init(false, &BorrowKey { key: &[0x01] }).unwrap();
        assert_eq!(
            c.process_block(&[0u8; 4], &mut out),
            Err(ToyError::BufferTooShort)
        );
    }
}
