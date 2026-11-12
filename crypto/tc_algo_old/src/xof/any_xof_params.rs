// What init takes, as plain data: each XOF checks these fields when it is initialized. Which ones an
// XOF takes is in its row of the table
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnyXofParams {
    customization: Option<Vec<u8>>,
    function_name: Option<Vec<u8>>,
    block_size: Option<usize>,
}

impl AnyXofParams {
    pub fn new() -> Self {
        Self::default()
    }

    // The customization string: S of NIST SP 800-185, Z of Ascon-CXOF128
    pub fn with_customization(mut self, customization: Vec<u8>) -> Self {
        self.customization = Some(customization);
        self
    }

    // The function name N of cSHAKE
    pub fn with_function_name(mut self, function_name: Vec<u8>) -> Self {
        self.function_name = Some(function_name);
        self
    }

    // The block size B of ParallelHash, in bytes
    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = Some(block_size);
        self
    }

    pub fn customization(&self) -> Option<&[u8]> {
        self.customization.as_deref()
    }

    pub fn function_name(&self) -> Option<&[u8]> {
        self.function_name.as_deref()
    }

    pub fn block_size(&self) -> Option<usize> {
        self.block_size
    }
}
