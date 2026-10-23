//! RFC 8018 A.3 PBES1 and RFC 7292 Appendix C PKCS#12 PBE parameters.
//!
//! ```text
//! PBEParameter ::= SEQUENCE {
//!     salt           OCTET STRING (SIZE(8)),
//!     iterationCount INTEGER }
//!
//! pkcs-12PbeParams ::= SEQUENCE {
//!     salt       OCTET STRING,
//!     iterations INTEGER }
//! ```
//!
//! Both have the same shape, so one type serves both. The salt length is left
//! to the scheme: PBES1 wants eight octets, PKCS#12 takes any.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A salt and an iteration count.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
/// use tc_asn1_pkcs::PbeParameter;
///
/// let params = PbeParameter::new(Asn1OctetString::new(&[1; 8]), 2048.into())?;
/// assert_eq!(params.encode_to_vec(&EncodingOptions::DER)?.len(), 16);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PbeParameter {
    salt: Asn1OctetString,
    iteration_count: Asn1Integer,
}

impl PbeParameter {
    /// Rejects a negative iteration count with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(salt: Asn1OctetString, iteration_count: Asn1Integer) -> Result<Self, Asn1Error> {
        if iteration_count.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            salt,
            iteration_count,
        })
    }

    /// Returns the salt.
    /// Variable time: branches only on the encoding structure.
    pub fn salt(&self) -> &Asn1OctetString {
        &self.salt
    }

    /// Returns the iteration count.
    /// Variable time: branches only on the encoding structure.
    pub fn iteration_count(&self) -> &Asn1Integer {
        &self.iteration_count
    }
}

impl fmt::Display for PbeParameter {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} salt octets, iteration count {}",
            self.salt.as_bytes().len(),
            self.iteration_count
        )
    }
}

impl DecodeInner for PbeParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let salt = fields.get()?;
        let iteration_count = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(salt, iteration_count)?))
    }
}

impl EncodeContent for PbeParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.salt.encoded_len(rules) + self.iteration_count.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.salt.encode(rules, &mut out[at..])?;
        at += self.iteration_count.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PbeParameter {}

impl Tagged for PbeParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PbeParameter {}

impl Encode for PbeParameter {
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
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::PbeParameter;

    /// The parameters of `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -iter 2048`.
    const OPENSSL: [u8; 16] = [
        0x30, 0x0e, 0x04, 0x08, 0x34, 0x9a, 0x85, 0xfd, 0x6c, 0x21, 0xed, 0x11, 0x02, 0x02, 0x08,
        0x00,
    ];

    #[test]
    fn openssl_pbe_parameters_decode_and_encode_back() {
        let (len, params) =
            PbeParameter::decode_der(&OPENSSL, &DecodingOptions::default()).unwrap();
        assert_eq!(len, OPENSSL.len());
        assert_eq!(
            params.salt().as_bytes(),
            [0x34, 0x9a, 0x85, 0xfd, 0x6c, 0x21, 0xed, 0x11]
        );
        assert_eq!(params.iteration_count().as_bytes(), [0x08, 0x00]);
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            OPENSSL
        );
        assert_eq!(params.to_string(), "8 salt octets, iteration count 2048");
    }

    #[test]
    fn pbe_parameters_take_any_salt_length_but_no_negative_count() {
        let params = PbeParameter::new(Asn1OctetString::new(&[7; 20]), 1.into()).unwrap();
        let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            PbeParameter::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
        assert_eq!(
            PbeParameter::new(Asn1OctetString::new(&[7; 8]), (-1).into()),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            PbeParameter::decode_der(&[0x30, 5, 4, 0, 2, 1, 0xff], &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
