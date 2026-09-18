//! The UTF-8 wire form of OID-IRI and RELATIVE-OID-IRI.
//!
//! Labels are checked for character set and hyphen placement per X.660
//! §7.3-7.5; no registry is consulted. Equality compares the raw string; the
//! A-label normalization needed to identify one registered node is left to the
//! caller. §7.5.3 lets implementations tolerate characters that may be
//! unreserved later; the listed scalar ranges are accepted here.

use alloc::string::String;
use core::fmt;

use super::tag;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// X.660 §7.5: non-empty; an integer label has no leading zero; a non-integer
/// label does not start or end with `-`, has no `--` in positions 3-4, and uses
/// only the unreserved ASCII and Unicode ranges.
fn valid_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.bytes().all(|b| b.is_ascii_digit()) {
        return label.len() == 1 || !label.starts_with('0');
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    let mut chars = label.chars();
    if chars.nth(2) == Some('-') && chars.next() == Some('-') {
        return false;
    }
    label.chars().all(|c| {
        let n = c as u32;
        c.is_ascii_alphanumeric()
            || matches!(c, '-' | '.' | '_' | '~')
            || matches!(n, 0xA0..=0xDFFE | 0xF900..=0xFDCF | 0xFDF0..=0xFFEF)
            || ((0x10000..=0xDFFFD).contains(&n) && n & 0xFFFF <= 0xFFFD)
            || (0xE1000..=0xEFFFD).contains(&n)
    })
}

/// The two types differ only in tag and whether the path starts with `/`.
macro_rules! iri {
    ($name:ident, $tag:ident, $absolute:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name {
            text: String,
        }

        impl $name {
            pub const TAG: &'static [u8] = tag::$tag;

            /// Validates the path and every label, then copies the text.
            /// Variable time: branches on the characters and path length.
            pub fn new(text: &str) -> Result<Self, Asn1Error> {
                let labels = if $absolute {
                    text.strip_prefix('/').ok_or(Asn1Error::MalformedValue)?
                } else {
                    text
                };
                if !labels.split('/').all(valid_label) {
                    return Err(Asn1Error::MalformedValue);
                }
                Ok(Self {
                    text: String::from(text),
                })
            }

            /// The raw UTF-8 path; no registry lookup or A-label conversion.
            pub fn as_str(&self) -> &str {
                &self.text
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.text)
            }
        }

        impl DecodeInner for $name {
            fn decode_inner(
                buff: &[u8],
                context: &mut DecodingContext,
            ) -> Result<(usize, Self), Asn1Error> {
                let element = crate::Asn1Ref::parse(buff, context)?;
                if element.tag() != Self::TAG {
                    return Err(Asn1Error::UnexpectedTag);
                }
                let value = Self::decode_content(element.value(), context)?;
                Ok((element.total_len(), value))
            }
        }

        impl Decode for $name {}
        impl Tagged for $name {
            const TAG: &'static [u8] = Self::TAG;
        }

        impl DecodeContent for $name {
            /// Validates UTF-8, the path and the labels. Variable time: branches on the contents.
            fn decode_content(
                value: &[u8],
                context: &mut DecodingContext,
            ) -> Result<Self, Asn1Error> {
                context.options().check_content_len(value.len())?;
                Self::new(core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?)
            }
        }

        impl EncodeContent for $name {
            fn content_len(&self, _: &EncodingOptions) -> usize {
                self.text.len()
            }

            fn encode_content(
                &self,
                _: &EncodingOptions,
                out: &mut [u8],
            ) -> Result<usize, Asn1Error> {
                let out = out
                    .get_mut(..self.text.len())
                    .ok_or(Asn1Error::BufferTooSmall)?;
                out.copy_from_slice(self.text.as_bytes());
                Ok(self.text.len())
            }
        }

        impl EncodeTagged for $name {}

        impl Encode for $name {
            fn encoded_len(&self, rules: &EncodingOptions) -> usize {
                self.encoded_len_tagged(Self::TAG, rules)
            }

            fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
                self.encode_tagged(Self::TAG, rules, out)
            }
        }
    };
}

iri!(
    Asn1OidIri,
    OID_IRI,
    true,
    r#"An absolute OID path starting with `/`; not a general URL.

# Examples

```
use tc_asn1::Asn1OidIri;
let oid = Asn1OidIri::new("/ISO/Registration_Authority/19785.CBEFF").unwrap();
assert!(oid.as_str().starts_with("/ISO/"));
assert!(Asn1OidIri::new("/ISO/01").is_err());
```"#
);
iri!(
    Asn1RelativeOidIri,
    RELATIVE_OID_IRI,
    false,
    r#"A relative OID path without the leading `/`.

# Examples

```
use tc_asn1::Asn1RelativeOidIri;
let oid = Asn1RelativeOidIri::new("\u{53F0}\u{5317}/0/TLV-encoded").unwrap();
assert_eq!(oid.as_str(), "\u{53F0}\u{5317}/0/TLV-encoded");
assert!(Asn1RelativeOidIri::new("/\u{53F0}\u{5317}").is_err());
```"#
);
