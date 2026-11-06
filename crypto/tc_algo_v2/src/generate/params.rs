use core::any::Any;

use tc_rsa::{RsaKey, RsaKeyGenerationParamsOwned};

use crate::Params;

impl Params for RsaKeyGenerationParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Params for RsaKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
