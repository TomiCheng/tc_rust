//! ASN.1 `BOOLEAN`。

use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::tag::BOOLEAN as TAG;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Boolean(pub bool);

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl<'a> crate::Decode<'a> for Asn1Boolean {
    fn try_decode(
        buff: &'a [u8],
        options: crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, options)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as crate::DecodeContent<'a>>::try_decode_content(element.value(), options)?;
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Asn1Boolean {
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        match value {
            // 寬鬆照 BER：任何非零都是真。DER 只允許 FF，靠往返比較判定。
            [octet] => Ok(Asn1Boolean(*octet != 0)),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl crate::EncodeContent for Asn1Boolean {
    /// BOOLEAN contents always occupy one octet.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len(&self, _: EncodingOptions) -> usize {
        1
    }

    /// Write FF for true or 00 for false, without the outer header or EOC.
    /// Return BufferTooSmall for an empty buffer; leave any remaining bytes unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encode_content(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let octet = out.first_mut().ok_or(Asn1Error::BufferTooSmall)?;
        *octet = u8::from(self.0).wrapping_neg();
        Ok(1)
    }
}

impl crate::EncodeTagged for Asn1Boolean {}

impl Encode for Asn1Boolean {
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
    use crate::EncodeContent;
    use crate::traits::Decode;

    #[test]
    fn content_encoding_supports_trait_objects_and_preserves_buffer_boundaries() {
        for rules in [
            EncodingOptions::Ber(crate::LengthForm::Definite),
            EncodingOptions::Ber(crate::LengthForm::Indefinite),
            EncodingOptions::Cer,
            EncodingOptions::Der,
        ] {
            for (value, expected) in [(Asn1Boolean(false), 0x00), (Asn1Boolean(true), 0xFF)] {
                let encoder: &dyn EncodeContent = &value;
                assert_eq!(encoder.content_len(rules), 1);
                assert_eq!(encoder.encode_content_to_vec(rules).unwrap(), [expected]);

                let mut out = [0xAA; 3];
                assert_eq!(encoder.encode_content(rules, &mut out), Ok(1));
                assert_eq!(out, [expected, 0xAA, 0xAA]);
                assert_eq!(
                    encoder.encode_content(rules, &mut []),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
        }
    }

    #[test]
    fn true_is_written_as_all_ones_and_false_as_zero() {
        let mut out = [0_u8; 4];
        assert_eq!(
            Asn1Boolean(true)
                .encode(EncodingOptions::Der, &mut out)
                .unwrap(),
            3
        );
        assert_eq!(&out[..3], &[0x01, 0x01, 0xFF]);
        assert_eq!(
            Asn1Boolean(false)
                .encode(EncodingOptions::Ber(crate::LengthForm::Definite), &mut out)
                .unwrap(),
            3
        );
        assert_eq!(&out[..3], &[0x01, 0x01, 0x00]);
    }

    #[test]
    fn a_non_canonical_true_re_encodes_as_der() {
        // 這就是往返比較判定「不是 DER」的機制：01 進來，FF 出去。
        let (_, b) = Asn1Boolean::try_decode(&[0x01, 0x01, 0x01], OPTIONS).unwrap();
        let mut out = [0_u8; 4];
        b.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..3], &[0x01, 0x01, 0xFF]);
    }

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn true_and_false_decode_from_their_single_octet() {
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x01, 0xFF], OPTIONS),
            Ok((3, Asn1Boolean(true)))
        );
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x01, 0x00], OPTIONS),
            Ok((3, Asn1Boolean(false)))
        );
    }

    #[test]
    fn any_non_zero_octet_is_true_under_ber() {
        for octet in [0x01_u8, 0x7F, 0x80, 0xFE] {
            assert_eq!(
                Asn1Boolean::try_decode_content(&[octet], OPTIONS),
                Ok(Asn1Boolean(true))
            );
        }
    }

    #[test]
    fn contents_of_any_length_but_one_are_rejected() {
        assert_eq!(
            Asn1Boolean::try_decode_content(&[], OPTIONS),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Boolean::try_decode_content(&[0xFF, 0xFF], OPTIONS),
            Err(Asn1Error::MalformedValue)
        );
    }
}
