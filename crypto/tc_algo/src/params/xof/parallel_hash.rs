use core::any::Any;

use crate::Params;

// What ParallelHash is set to by Xof::init: the block size B in bytes and the customization string
// S of SP 800-185, S empty unless set. B is part of what is hashed, so both sides must agree on it.
// Whether B will do is for init to judge, not checked here
#[derive(Clone, Debug)]
pub struct ParallelHashParams {
    block_size: usize,
    customization: Vec<u8>,
}

impl ParallelHashParams {
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size,
            customization: Vec::new(),
        }
    }

    pub fn with_customization(mut self, customization: Vec<u8>) -> Self {
        self.customization = customization;
        self
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn customization(&self) -> &[u8] {
        &self.customization
    }
}

impl Params for ParallelHashParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
