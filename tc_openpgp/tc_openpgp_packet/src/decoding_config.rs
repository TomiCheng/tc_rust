use crate::PacketHeaderFormat;

/// Options for decoding an OpenPGP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodingConfig {
    /// Maximum total number of body bytes, including all partial chunks.
    pub max_body_len: u64,
    /// Required packet header format. None accepts either supported format.
    pub header_format: Option<PacketHeaderFormat>,
}

impl Default for DecodingConfig {
    fn default() -> Self {
        Self {
            max_body_len: u64::MAX,
            header_format: None,
        }
    }
}
