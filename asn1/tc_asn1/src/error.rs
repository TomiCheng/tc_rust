use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Asn1Error {
    Truncated,
    TrailingData,
    NotDer,
    NonMinimalTag,
    TagOverflow,
    LengthOverflow,
    UnexpectedTag,
    MalformedValue,
    InexactValue,
    DepthExceeded,
    ContentLengthExceeded,
    ChildrenExceeded,
    BufferTooSmall,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Truncated => "input ended inside a TLV",
            Self::TrailingData => "unexpected bytes after the encoded value",
            Self::NotDer => "encoding is not DER",
            Self::NonMinimalTag => "tag number is not in the shortest form",
            Self::TagOverflow => "tag number exceeds the supported range",
            Self::LengthOverflow => "length exceeds the platform's usize",
            Self::UnexpectedTag => "tag does not match the expected type",
            Self::MalformedValue => "contents are not valid for this type",
            Self::InexactValue => "value cannot be represented exactly by the target type",
            Self::DepthExceeded => "nesting is deeper than the allowed limit",
            Self::ContentLengthExceeded => "contents exceed the configured length limit",
            Self::ChildrenExceeded => "child count exceeds the configured limit",
            Self::BufferTooSmall => "output buffer is too small",
        })
    }
}

impl core::error::Error for Asn1Error {}
