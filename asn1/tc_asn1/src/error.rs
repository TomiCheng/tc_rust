//! Errors reported during ASN.1 parsing and encoding.

use core::fmt;

/// An error encountered while parsing or encoding ASN.1 data.
///
/// Each variant identifies a specific failure rather than a generic invalid
/// encoding, helping callers diagnose interoperability problems.
/// Additional variants may be introduced; downstream matches must include a
/// fallback arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Asn1Error {
    /// The input ends before a complete tag-length-value (TLV) element is available.
    Truncated,

    /// Unexpected bytes remain after a complete value.
    TrailingData,

    /// The value can be decoded, but its DER re-encoding differs from the input.
    NotDer,

    /// The tag number uses a nonminimal high-tag-number encoding.
    NonMinimalTag,

    /// The tag number exceeds the range supported by this implementation.
    TagOverflow,

    /// A length exceeds the range representable by the platform's `usize`.
    LengthOverflow,

    /// The tag does not match the type or encoded form expected at this position.
    UnexpectedTag,

    /// The content bytes do not satisfy the selected type's encoding rules.
    MalformedValue,

    /// The value cannot be represented exactly by the target type.
    /// Conversions do not round, overflow, or underflow to produce a result.
    InexactValue,

    /// Nesting exceeds the configured depth budget.
    DepthExceeded,

    /// Contents exceed the configured per-element byte limit.
    ContentLengthExceeded,

    /// A constructed value exceeds the configured direct-child limit.
    ChildrenExceeded,

    /// The caller-provided output buffer is too small.
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
