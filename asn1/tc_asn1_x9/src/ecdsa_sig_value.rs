//! X9.62 ECDSA signature values.
//!
//! ```text
//! ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
//! ```
//!
//! Both values must be positive. Their upper bound is n-1, but the subgroup
//! order is not carried here and must be checked by the signature verifier.
//! Reversing r and s cannot be detected by ASN.1 decoding.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

/// An ECDSA signature's two positive, arbitrary-precision integers.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::EcdsaSigValue;
///
/// let signature = EcdsaSigValue::new(128.into(), 1.into())?;
/// let der = signature.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(EcdsaSigValue::decode_der(&der, &DecodingOptions::default())?.1, signature);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EcdsaSigValue {
    r: Asn1Integer,
    s: Asn1Integer,
}

impl EcdsaSigValue {
    /// Rejects zero or negative values with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(r: Asn1Integer, s: Asn1Integer) -> Result<Self, Asn1Error> {
        if r.is_negative() || r.as_bytes() == [0] || s.is_negative() || s.as_bytes() == [0] {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { r, s })
    }

    /// Returns the first signature integer.
    /// Variable time: branches only on the encoding structure.
    pub fn r(&self) -> &Asn1Integer {
        &self.r
    }

    /// Returns the second signature integer.
    /// Variable time: branches only on the encoding structure.
    pub fn s(&self) -> &Asn1Integer {
        &self.s
    }
}

impl fmt::Display for EcdsaSigValue {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.r, self.s)
    }
}

impl DecodeInner for EcdsaSigValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let r = fields.get()?;
        let s = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(r, s)?))
    }
}

impl EncodeContent for EcdsaSigValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.r.encoded_len(rules) + self.s.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.r.encode(rules, out)?;
        Ok(at + self.s.encode(rules, &mut out[at..])?)
    }
}

impl Decode for EcdsaSigValue {}

impl Tagged for EcdsaSigValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EcdsaSigValue {}

impl Encode for EcdsaSigValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString};

    use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::EcdsaSigValue;

    #[test]
    fn signature_integers_keep_their_sign_octets_and_display_in_order() {
        let value = EcdsaSigValue::new(128.into(), 1.into()).unwrap();
        let wire = b"\x30\x07\x02\x02\x00\x80\x02\x01\x01";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            EcdsaSigValue::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        assert_eq!(value.to_string(), format!("{}, {}", value.r(), value.s()));
        let large =
            EcdsaSigValue::new(Asn1Integer::from_unsigned_bytes(&[0xff; 80]), 1.into()).unwrap();
        let wire = large.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            EcdsaSigValue::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            large
        );
    }

    #[test]
    fn zero_and_negative_signature_integers_are_rejected_in_either_position() {
        for (r, s) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
            assert_eq!(
                EcdsaSigValue::new(r.into(), s.into()),
                Err(Asn1Error::MalformedValue)
            );
            let wire = [0x30, 6, 2, 1, r as u8, 2, 1, s as u8];
            assert_eq!(
                EcdsaSigValue::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn signature_fields_must_be_two_integers_with_no_trailing_value() {
        for (wire, error) in [
            (&b"\x30\x03\x02\x01\x01"[..], Asn1Error::Truncated),
            (&b"\x30\x02\x05\x00"[..], Asn1Error::UnexpectedTag),
            (
                &b"\x30\x08\x02\x01\x01\x02\x01\x02\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                EcdsaSigValue::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
