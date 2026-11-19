/// Payload format octet of an OpenPGP Literal Data packet.
///
/// See [RFC 9580, Section 5.9](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.9).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum LiteralDataFormat {
    /// Binary data (`b`).
    Binary,
    /// UTF-8 text with CRLF line endings (`u`).
    Utf8,
    /// Deprecated text format with unspecified character encoding (`t`).
    LegacyText,
    /// An octet without a named variant.
    Unknown(u8),
}

impl From<u8> for LiteralDataFormat {
    fn from(value: u8) -> Self {
        match value {
            b'b' => Self::Binary,
            b'u' => Self::Utf8,
            b't' => Self::LegacyText,
            other => Self::Unknown(other),
        }
    }
}

impl From<LiteralDataFormat> for u8 {
    fn from(format: LiteralDataFormat) -> Self {
        match format {
            LiteralDataFormat::Binary => b'b',
            LiteralDataFormat::Utf8 => b'u',
            LiteralDataFormat::LegacyText => b't',
            LiteralDataFormat::Unknown(value) => value,
        }
    }
}
