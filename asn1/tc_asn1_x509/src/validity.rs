//! RFC 5280 §4.1.2.5 `Validity`.
//!
//! ```text
//! Validity ::= SEQUENCE {
//!     notBefore      Time,
//!     notAfter       Time
//! }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged, tag,
};

use crate::Time;

/// The period a certificate is valid for; the end may not precede the start.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    pub fn new(not_before: Time, not_after: Time) -> Result<Self, Asn1Error> {
        if not_after < not_before {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    pub fn not_before(&self) -> Time {
        self.not_before
    }

    pub fn not_after(&self) -> Time {
        self.not_after
    }
}

impl DecodeInner for Validity {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let not_before: Time = children.get()?;
        let not_after: Time = children.get()?;
        children.end()?;
        Ok((element.total_len(), Self::new(not_before, not_after)?))
    }
}

impl Decode for Validity {}

impl Tagged for Validity {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for Validity {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.not_before.encoded_len(rules) + self.not_after.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.not_before.encode(rules, out)?;
        at += self.not_after.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for Validity {}

impl Encode for Validity {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Validity;
    use crate::Time;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    #[test]
    fn a_validity_period_round_trips_across_the_2050_boundary() {
        let not_before = Time::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = Time::new(2051, 1, 1, 0, 0, 0).unwrap();
        let validity = Validity::new(not_before, not_after).unwrap();
        let out = validity.encode_to_vec(&der()).unwrap();
        assert_eq!(out, b"\x30\x20\x17\x0d260101000000Z\x18\x0f20510101000000Z");
        let (used, decoded) = Validity::decode(&out, &DecodingOptions::default()).unwrap();
        assert_eq!((used, decoded), (out.len(), validity));
        assert_eq!(decoded.not_before().year(), 2026);
        assert_eq!(decoded.not_after().year(), 2051);
    }

    #[test]
    fn the_period_must_not_run_backwards_when_built_or_decoded() {
        let earlier = Time::new(2026, 1, 1, 0, 0, 0).unwrap();
        let later = Time::new(2027, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(
            Validity::new(later, earlier),
            Err(Asn1Error::MalformedValue)
        ));
        let backwards = b"\x30\x1e\x17\x0d270101000000Z\x17\x0d260101000000Z";
        assert!(matches!(
            Validity::decode(backwards, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_missing_or_extra_time_is_rejected() {
        assert!(matches!(
            Validity::decode(
                b"\x30\x0f\x17\x0d260101000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::Truncated)
        ));
        assert!(matches!(
            Validity::decode(
                b"\x30\x2d\x17\x0d260101000000Z\x17\x0d270101000000Z\x17\x0d280101000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
    }
}
