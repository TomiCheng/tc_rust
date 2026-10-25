//! Allocation-free adapters for already-validated public encoding values.

use tc_asn1::{Asn1Error, Encode, EncodeContent, EncodeTagged, EncodingOptions, tag};

/// A borrowed OID content encoding, validated by Asn1Oid or NamedOid.
pub(crate) struct OidRef<'a>(pub(crate) &'a [u8]);

impl EncodeContent for OidRef<'_> {
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        self.0.len()
    }

    fn encode_content(&self, _rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..self.0.len())
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(self.0);
        Ok(self.0.len())
    }
}

impl EncodeTagged for OidRef<'_> {}

impl Encode for OidRef<'_> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(tag::OBJECT_IDENTIFIER, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(tag::OBJECT_IDENTIFIER, rules, out)
    }
}

/// A nonnegative INTEGER encoded directly from a stack-sized exponent.
pub(crate) struct Exponent(pub(crate) u32);

impl Exponent {
    fn first(&self) -> usize {
        (self.0.leading_zeros() as usize / 8).min(3)
    }
}

impl EncodeContent for Exponent {
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        let bytes = self.0.to_be_bytes();
        let first = self.first();
        4 - first + usize::from(bytes[first] & 0x80 != 0)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let bytes = self.0.to_be_bytes();
        let first = self.first();
        let len = self.content_len(rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        let sign = usize::from(bytes[first] & 0x80 != 0);
        if sign != 0 {
            out[0] = 0;
        }
        out[sign..].copy_from_slice(&bytes[first..]);
        Ok(len)
    }
}

impl EncodeTagged for Exponent {}

impl Encode for Exponent {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(tag::INTEGER, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(tag::INTEGER, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Asn1Integer, Asn1Oid, Encode, EncodeContent, EncodingOptions};

    use super::{Exponent, OidRef};

    #[test]
    fn stack_exponents_match_asn1_integers_at_every_byte_and_sign_boundary() {
        for value in [
            0,
            1,
            127,
            128,
            255,
            256,
            32767,
            32768,
            65535,
            65536,
            0x7fffff,
            0x800000,
            0xffffff,
            0x1000000,
            0x7fffffff,
            0x80000000,
            u32::MAX,
        ] {
            for rules in [
                EncodingOptions::BER,
                EncodingOptions::CER,
                EncodingOptions::DER,
            ] {
                let exponent = Exponent(value);
                let expected = Asn1Integer::from(value);
                assert_eq!(
                    exponent.encode_to_vec(&rules).unwrap(),
                    expected.encode_to_vec(&rules).unwrap()
                );
                assert_eq!(exponent.encoded_len(&rules), expected.encoded_len(&rules));
                let mut short = [0u8; 5];
                assert_eq!(
                    exponent.encode_content(&rules, &mut short[..exponent.content_len(&rules) - 1]),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
        }
    }

    #[test]
    fn borrowed_oids_match_owned_encodings_without_copying_their_contents() {
        let oid: Asn1Oid = "1.2.840.10045.1.1".parse().unwrap();
        let borrowed = OidRef(oid.as_bytes());
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::CER,
            EncodingOptions::DER,
        ] {
            assert_eq!(
                borrowed.encode_to_vec(&rules).unwrap(),
                oid.encode_to_vec(&rules).unwrap()
            );
            assert_eq!(borrowed.encoded_len(&rules), oid.encoded_len(&rules));
        }
        assert_eq!(
            borrowed.encode_content(&EncodingOptions::DER, &mut []),
            Err(Asn1Error::BufferTooSmall)
        );
    }
}
