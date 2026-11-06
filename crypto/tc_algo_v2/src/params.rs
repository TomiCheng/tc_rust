use core::any::Any;

use tc_block_cipher::KeyOwned;

use crate::Params;

impl Params for KeyOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
