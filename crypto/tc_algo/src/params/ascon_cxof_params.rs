use core::any::Any;

use crate::Params;

// What Ascon-CXOF128 is set to by Xof::init: the customization string Z of SP 800-232, empty
// unless set. Its length is for init to judge, not checked here
#[derive(Clone, Debug, Default)]
pub struct AsconCXofParams {
    customization: Vec<u8>,
}

impl AsconCXofParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_customization(mut self, customization: Vec<u8>) -> Self {
        self.customization = customization;
        self
    }

    pub fn customization(&self) -> &[u8] {
        &self.customization
    }
}

impl Params for AsconCXofParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
