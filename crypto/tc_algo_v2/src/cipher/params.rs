use core::any::Any;

use tc_block_cipher::KeyOwned;
use tc_block_modes::KeyWithIvOwned;

use crate::Params;

impl Params for KeyOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
