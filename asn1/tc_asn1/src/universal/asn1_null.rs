//! ASN.1 `NULL`。

use crate::DecodingContext;
use crate::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};
use core::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Asn1Null;

impl Asn1Null {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::NULL;
}

impl Display for Asn1Null {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("NULL")
    }
}

impl<'a> crate::DecodeInner<'a> for Asn1Null {
    fn decode_inner(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value = <Self as crate::DecodeContent<'a>>::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as crate::DecodeContent<'a>>::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl<'a> crate::Decode<'a> for Asn1Null {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl<'a> DecodeContent<'a> for Asn1Null {
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if value.is_empty() {
            Ok(Asn1Null)
        } else {
            Err(Asn1Error::MalformedValue)
        }
    }

    fn decode_content_der(
        value: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<Self, crate::Asn1Error> {
        crate::decoding::decode_der_content::<Self>(value, context)
    }
}

impl crate::EncodeContent for Asn1Null {
    /// Length of the contents, excluding the outer header and EOC.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        0
    }

    /// Write only the contents, leaving any remaining output bytes unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encode_content(&self, _: &EncodingOptions, _: &mut [u8]) -> Result<usize, Asn1Error> {
        Ok(0)
    }
}

impl crate::EncodeTagged for Asn1Null {}

impl Encode for Asn1Null {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodingOptions;
    use crate::EncodingType;
    use crate::traits::Decode;

    #[test]
    fn null_encodes_as_the_two_byte_sequence() {
        let mut out = [0xAA_u8; 4];
        let written = Asn1Null
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &[0x05, 0x00]);
        assert_eq!(out[2], 0xAA, "只寫前兩個位元組");
        assert_eq!(
            written,
            Asn1Null.encoded_len(&EncodingOptions::new(EncodingType::Der))
        );
    }

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT.get(), 16 * 1024 * 1024, 65_536);

    #[test]
    fn null_decodes_and_reports_its_two_bytes() {
        assert_eq!(
            Asn1Null::decode(&[0x05, 0x00, 0xAA], &OPTIONS),
            Ok((2, Asn1Null))
        );
    }

    #[test]
    fn a_redundant_ber_length_form_still_decodes_as_null() {
        assert_eq!(
            Asn1Null::decode(&[0x05, 0x81, 0x00], &OPTIONS),
            Ok((3, Asn1Null))
        );
    }

    #[test]
    fn a_null_carrying_contents_is_rejected() {
        assert_eq!(
            Asn1Null::decode(&[0x05, 0x01, 0x00], &OPTIONS),
            Err(Asn1Error::MalformedValue)
        );
        // IMPLICIT 那條路（直接餵內容）也擋得住。
        assert_eq!(
            Asn1Null::decode_content(&[0x00], &mut DecodingContext::new(&OPTIONS)),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn the_schema_checks_tags_a_tag_other_than_null_is_rejected() {
        assert_eq!(
            crate::Fields::new(&[0x02, 0x00], &mut DecodingContext::new(&OPTIONS))
                .and_then(|mut fields| fields.required::<Asn1Null>(Asn1Null::TAG)),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
