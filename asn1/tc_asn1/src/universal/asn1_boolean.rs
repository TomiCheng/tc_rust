//! ASN.1 `BOOLEAN`。

use crate::depth::Depth;
use crate::error::Asn1Error;
use crate::traits::TryDecodeContent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Boolean(pub bool);

impl<'a> TryDecodeContent<'a> for Asn1Boolean {
    const TAG: &'static [u8] = &[0x01];

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        match value {
            // 寬鬆照 BER：任何非零都是真。DER 只允許 FF，靠往返比較判定。
            [octet] => Ok(Asn1Boolean(*octet != 0)),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TryDecode;

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
