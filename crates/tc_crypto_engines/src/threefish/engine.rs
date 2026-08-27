//! The Threefish engine (scaffold).
//!
//! Currently a bare shell that wires the [`BlockCipher`] trait to Threefish's
//! associated parameter and error types; every operation is still `todo!()`.

use tc_crypto_core::BlockCipher;

use super::{ThreefishError, ThreefishParams};

/// The Threefish tweakable block cipher (bc `ThreefishEngine`).
///
/// Fields (key schedule, tweak schedule, block size, direction) will be added as
/// the implementation lands.
pub struct ThreefishEngine;

impl BlockCipher for ThreefishEngine {
    // 參數為擁有式、無 lifetime,GAT 的 'a 在此忽略。
    type Params<'a> = ThreefishParams;
    type Error = ThreefishError;

    fn algorithm_name(&self) -> &str {
        todo!()
    }

    fn block_size(&self) -> usize {
        todo!()
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        _params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn process_block(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }
}
