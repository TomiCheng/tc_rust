use core::any::Any;

use crate::Params;

// What TupleHash is set to by Xof::init: the customization string S of SP 800-185, empty unless
// set. Nothing is checked here
#[derive(Clone, Debug, Default)]
pub struct TupleHashParams {
    customization: Vec<u8>,
}

impl TupleHashParams {
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

impl Params for TupleHashParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
