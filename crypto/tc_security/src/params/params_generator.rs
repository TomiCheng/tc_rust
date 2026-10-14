use rand::CryptoRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tc_buffered_cipher::BufferedCipher;

use super::{AnyParams, ParamGenParams, ParamsEntry, table};
use crate::SecurityError;

pub struct ParamsGenerator {
    entry: ParamsEntry,
    key: AnyParams,
    block_size: usize,
    rng: Box<dyn CryptoRng + Send>,
}

impl ParamsGenerator {
    pub(super) fn new(entry: ParamsEntry, key: AnyParams) -> Self {
        Self {
            entry,
            key,
            block_size: entry.cipher_entry().cipher().block_size(),
            rng: Box::new(UnwrapErr(SysRng)),
        }
    }

    pub fn with_rng(&mut self, rng: impl CryptoRng + Send + 'static) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    pub fn init(&mut self, params: &ParamGenParams) -> Result<(), SecurityError> {
        match *params {}
    }

    #[allow(unreachable_code, reason = "沒開任何 cipher 演算法時 Algorithm 沒有值")]
    pub fn generate(&mut self) -> Result<AnyParams, SecurityError> {
        let cipher = self.entry.cipher_entry();
        let generate = match cipher.mode() {
            Some(mode) => table::for_mode(mode),
            None => table::for_algorithm(cipher.algo()),
        }
        .ok_or(SecurityError::UnknownCipher)?;
        Ok(generate(&self.key, self.block_size, &mut *self.rng))
    }
}
