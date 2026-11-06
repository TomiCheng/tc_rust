use core::any::Any;

use tc_aead_cipher::AeadParamsOwned;
use tc_block_modes::KeyWithIvOwned;

use crate::Params;

impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Params for AeadParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
