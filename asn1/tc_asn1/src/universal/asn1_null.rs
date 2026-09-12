//! ASN.1 `NULL`。

use crate::depth::Depth;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};
use core::fmt::{Display, Formatter};

use super::tag::NULL as TAG;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Asn1Null;

impl Display for Asn1Null {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("NULL")
    }
}

impl<'a> DecodeContent<'a> for Asn1Null {
    const TAG: &'static [u8] = TAG;

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        if value.is_empty() {
            Ok(Asn1Null)
        } else {
            Err(Asn1Error::MalformedValue)
        }
    }
}

impl crate::EncodeContent for Asn1Null {
    /// Length of the contents, excluding the outer header and EOC.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len(&self, _: EncodingOptions) -> usize {
        0
    }

    /// Write only the contents, leaving any remaining output bytes unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encode_content(&self, _: EncodingOptions, _: &mut [u8]) -> Result<usize, Asn1Error> {
        Ok(0)
    }
}

impl crate::EncodeTagged for Asn1Null {}

impl Encode for Asn1Null {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, TAG, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;

    #[test]
    fn null_encodes_as_the_two_byte_sequence() {
        let mut out = [0xAA_u8; 4];
        let written = Asn1Null.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &[0x05, 0x00]);
        assert_eq!(out[2], 0xAA, "只寫前兩個位元組");
        assert_eq!(written, Asn1Null.encoded_len(EncodingOptions::Der));
    }

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn null_decodes_and_reports_its_two_bytes() {
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x00, 0xAA], DEPTH),
            Ok((2, Asn1Null))
        );
    }

    #[test]
    fn a_redundant_ber_length_form_still_decodes_as_null() {
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x81, 0x00], DEPTH),
            Ok((3, Asn1Null))
        );
    }

    #[test]
    fn a_null_carrying_contents_is_rejected() {
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x01, 0x00], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
        // IMPLICIT 那條路（直接餵內容）也擋得住。
        assert_eq!(
            Asn1Null::try_decode_content(&[0x00], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn a_tag_other_than_null_is_rejected() {
        assert_eq!(
            Asn1Null::try_decode(&[0x02, 0x00], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
