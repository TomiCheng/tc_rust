//! ASN.1 `BOOLEAN`。

use crate::depth::Depth;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode, EncodeContent};

use super::tag::BOOLEAN as TAG;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Boolean(pub bool);

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl<'a> DecodeContent<'a> for Asn1Boolean {
    const TAG: &'static [u8] = TAG;

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        match value {
            // 寬鬆照 BER：任何非零都是真。DER 只允許 FF，靠往返比較判定。
            [octet] => Ok(Asn1Boolean(*octet != 0)),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl EncodeContent for Asn1Boolean {
    type Error = Asn1Error;

    /// BOOLEAN contents always occupy one octet.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len_v2(&self, _: EncodingOptions) -> usize {
        1
    }

    /// Write FF for true or 00 for false, without the outer header or EOC.
    /// Return BufferTooSmall for an empty buffer; leave any remaining bytes unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encode_content_v2(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let octet = out.first_mut().ok_or(Asn1Error::BufferTooSmall)?;
        *octet = u8::from(self.0).wrapping_neg();
        Ok(1)
    }
}

impl Encode for Asn1Boolean {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingOptions) -> usize {
        1
    }
    /// 真永遠寫 `FF`：三種規則下都合法，而且直接是 DER 形式。
    fn encode_content(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[0] = u8::from(self.0).wrapping_neg(); // true → 1 → 0xFF，沒有分支
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                let encoder: &dyn EncodeContent<Error = Asn1Error> = &value;
                assert_eq!(encoder.content_len_v2(rules), 1);
                assert_eq!(encoder.encode_content_to_vec(rules).unwrap(), [expected]);

                let mut out = [0xAA; 3];
                assert_eq!(encoder.encode_content_v2(rules, &mut out), Ok(1));
                assert_eq!(out, [expected, 0xAA, 0xAA]);
                assert_eq!(
                    encoder.encode_content_v2(rules, &mut []),
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
        let (_, b) = Asn1Boolean::try_decode(&[0x01, 0x01, 0x01], DEPTH).unwrap();
        let mut out = [0_u8; 4];
        b.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..3], &[0x01, 0x01, 0xFF]);
    }

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn true_and_false_decode_from_their_single_octet() {
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x01, 0xFF], DEPTH),
            Ok((3, Asn1Boolean(true)))
        );
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x01, 0x00], DEPTH),
            Ok((3, Asn1Boolean(false)))
        );
    }

    #[test]
    fn any_non_zero_octet_is_true_under_ber() {
        for octet in [0x01_u8, 0x7F, 0x80, 0xFE] {
            assert_eq!(
                Asn1Boolean::try_decode_content(&[octet], DEPTH),
                Ok(Asn1Boolean(true))
            );
        }
    }

    #[test]
    fn contents_of_any_length_but_one_are_rejected() {
        assert_eq!(
            Asn1Boolean::try_decode_content(&[], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Boolean::try_decode_content(&[0xFF, 0xFF], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }
}
