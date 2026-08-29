//! Electronic Codebook (ECB) mode, ported from Bouncy Castle's `EcbBlockCipher`.
//!
//! ECB applies the underlying cipher to each block independently. It adds no
//! chaining state, so every operation delegates straight through — which is why
//! it also carries the underlying cipher's parameter and error types unchanged.
//!
//! Identical plaintext blocks encrypt to identical ciphertext blocks, so ECB
//! leaks structure and is unsuitable for most protocols; it is provided for
//! completeness and for algorithms that build on the raw permutation.

use alloc::string::String;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

/// ECB mode over the block cipher `E` (bc `EcbBlockCipher`).
pub struct EcbBlockCipher<E> {
    /// The underlying block cipher.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
}

impl<E: BlockCipher> EcbBlockCipher<E> {
    /// Wraps the given block cipher in ECB mode.
    pub fn new(cipher: E) -> Self {
        let mut mode = Self {
            cipher,
            name: String::new(),
        };
        mode.refresh_name();
        mode
    }

    /// Rebuilds `"<cipher>/ECB"`.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine（如 Threefish）要等 keying
    /// 之後才知道自己的名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 4);
        name.push_str(base);
        name.push_str("/ECB");
        self.name = name;
    }
}

impl<E: BlockCipher> BlockCipher for EcbBlockCipher<E> {
    /// ECB introduces no failure of its own, so it reports the underlying
    /// cipher's errors unchanged — an ECB-wrapped engine stays interchangeable
    /// with a bare one.
    type Error = E::Error;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_block(input, output)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for EcbBlockCipher<E> {
    /// ECB takes no parameters of its own (no IV), so it passes the underlying
    /// cipher's parameters straight through.
    type Params<'a> = E::Params<'a>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.cipher.init(direction, params)?;
        self.refresh_name();
        Ok(())
    }
}
