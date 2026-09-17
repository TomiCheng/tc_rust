use crate::EncodingType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingOptions {
    encoding_type: EncodingType,
}

impl EncodingOptions {
    pub const fn new(encoding_type: EncodingType) -> Self {
        Self { encoding_type }
    }

    pub const fn encoding_type(&self) -> EncodingType {
        self.encoding_type
    }

    pub const fn is_canonical(&self) -> bool {
        self.encoding_type.is_canonical()
    }
}
