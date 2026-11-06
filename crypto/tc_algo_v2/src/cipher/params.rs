use core::any::Any;

#[cfg(feature = "aes")]
use tc_aead_cipher::AeadParamsOwned;
use tc_block_modes::KeyWithIvOwned;

use crate::Params;

impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "aes")]
impl Params for AeadParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
