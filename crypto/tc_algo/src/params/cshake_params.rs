use core::any::Any;

use crate::Params;

// What cSHAKE is set to by Xof::init: the function name N and the customization string S of
// SP 800-185, both empty unless set, which is plain SHAKE. Nothing is checked here
#[derive(Clone, Debug, Default)]
pub struct CShakeParams {
    function_name: Vec<u8>,
    customization: Vec<u8>,
}

impl CShakeParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_function_name(mut self, function_name: Vec<u8>) -> Self {
        self.function_name = function_name;
        self
    }

    pub fn with_customization(mut self, customization: Vec<u8>) -> Self {
        self.customization = customization;
        self
    }

    pub fn function_name(&self) -> &[u8] {
        &self.function_name
    }

    pub fn customization(&self) -> &[u8] {
        &self.customization
    }
}

impl Params for CShakeParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
