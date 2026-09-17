use crate::Asn1Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodingOptions {
    depth: u32,
    max_content_len: usize,
    max_children: usize,
}

impl DecodingOptions {
    pub(crate) fn check_content_len(&self, len: usize) -> Result<(), Asn1Error> {
        if len > self.max_content_len {
            Err(Asn1Error::ContentLengthExceeded)
        } else {
            Ok(())
        }
    }

    pub const fn new(depth: u32, max_content_len: usize, max_children: usize) -> Self {
        Self {
            depth,
            max_content_len,
            max_children,
        }
    }

    pub const fn depth(&self) -> u32 {
        self.depth
    }

    pub const fn max_content_len(&self) -> usize {
        self.max_content_len
    }

    pub const fn max_children(&self) -> usize {
        self.max_children
    }
}

impl Default for DecodingOptions {
    fn default() -> Self {
        Self {
            depth: 32,
            max_content_len: 16 * 1024 * 1024,
            max_children: 65_536,
        }
    }
}
