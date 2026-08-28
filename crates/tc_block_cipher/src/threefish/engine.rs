//! The Threefish engine.
//!
//! The engine starts at a default block size, so its size/name accessors always
//! answer; [`BlockCipher::init`] infers the block size from the validated key,
//! rebuilding the key schedule (and resizing it only when the block size actually
//! changes). Per-variant round functions live in [`super::cipher`].

use alloc::vec::Vec;

use tc_crypto_core::BlockCipher;

use super::cipher::{self, C_240};
use super::{BlockCipherError, ThreefishParams};

/// The default block size of a freshly constructed engine, before any `init`.
const DEFAULT_BLOCK_SIZE: usize = 32;

/// The Threefish tweakable block cipher (bc `ThreefishEngine`).
///
/// Construct with [`new`](ThreefishEngine::new) (or [`Default`]); the key, tweak
/// and — via the params — the block size arrive at [`BlockCipher::init`].
pub struct ThreefishEngine {
    /// 目前分組:建構時為預設值,init 時採用 params 的分組。
    block_size: usize,
    /// 展開金鑰排程:nw 個金鑰字 + parity 字(共 nw+1);init 前為空 = 未初始化。
    kw: Vec<u64>,
    /// tweak 排程:t0, t1, t0 ^ t1。
    t: [u64; 3],
    /// true = 加密,false = 解密。
    for_encryption: bool,
}

impl ThreefishEngine {
    /// Creates a Threefish engine at the default block size (overridden by the
    /// first [`init`](BlockCipher::init)).
    pub fn new() -> Self {
        ThreefishEngine {
            block_size: DEFAULT_BLOCK_SIZE,
            kw: Vec::new(),
            t: [0; 3],
            for_encryption: false,
        }
    }

    /// 目前分組的字數(nw = 分組位元組 / 8)。
    fn words(&self) -> usize {
        self.block_size / 8
    }
}

impl Default for ThreefishEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for ThreefishEngine {
    // 參數為擁有式、無 lifetime,GAT 的 'a 在此忽略。
    type Params<'a> = ThreefishParams;
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        match self.block_size {
            32 => "Threefish-256",
            64 => "Threefish-512",
            128 => "Threefish-1024",
            _ => unreachable!("ThreefishParams validates the key length"),
        }
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn init(
        &mut self,
        for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // Threefish 的 key 與 block 等長;由已驗證的 key 長度選擇變體。
        self.block_size = params.key_len();
        let nw = self.words();
        if self.kw.len() != nw + 1 {
            self.kw.resize(nw + 1, 0);
        }

        // 金鑰排程:kw[0..nw] = 金鑰字(小端),kw[nw] = C_240 ^ 所有金鑰字。
        // params 已保證 key 長度 == 分組,無需再驗。
        let key = params.key();
        let mut parity = C_240;
        for i in 0..nw {
            let word = u64::from_le_bytes(key[i * 8..i * 8 + 8].try_into().unwrap());
            self.kw[i] = word;
            parity ^= word;
        }
        self.kw[nw] = parity;

        // tweak 排程:無 tweak 時採全零。
        let (t0, t1) = match params.tweak() {
            Some(tw) => (
                u64::from_le_bytes(tw[0..8].try_into().unwrap()),
                u64::from_le_bytes(tw[8..16].try_into().unwrap()),
            ),
            None => (0, 0),
        };
        self.t = [t0, t1, t0 ^ t1];

        self.for_encryption = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let nw = self.words();
        // kw 未達 nw+1 表示尚未 init。
        if self.kw.len() != nw + 1 {
            return Err(BlockCipherError::NotInitialised);
        }
        let bytes = self.block_size;
        if input.len() < bytes || output.len() < bytes {
            return Err(BlockCipherError::BufferTooShort);
        }

        // 小端位元組 → 字。
        let mut in_words = [0u64; 16];
        for i in 0..nw {
            in_words[i] = u64::from_le_bytes(input[i * 8..i * 8 + 8].try_into().unwrap());
        }

        let mut out_words = [0u64; 16];
        let variant = cipher::variant(self.block_size);
        let (in_w, out_w) = (&in_words[..nw], &mut out_words[..nw]);
        if self.for_encryption {
            cipher::encrypt(&variant, &self.kw, &self.t, in_w, out_w);
        } else {
            cipher::decrypt(&variant, &self.kw, &self.t, in_w, out_w);
        }

        // 字 → 小端位元組。
        for i in 0..nw {
            output[i * 8..i * 8 + 8].copy_from_slice(&out_words[i].to_le_bytes());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_block_size_before_init() {
        let e = ThreefishEngine::new();
        assert_eq!(e.block_size(), 32);
        assert_eq!(e.algorithm_name(), "Threefish-256");
    }

    #[test]
    fn process_block_before_init_errors() {
        let mut e = ThreefishEngine::new();
        let mut out = [0u8; 32];
        assert_eq!(
            e.process_block(&[0u8; 32], &mut out),
            Err(BlockCipherError::NotInitialised)
        );
    }
}
