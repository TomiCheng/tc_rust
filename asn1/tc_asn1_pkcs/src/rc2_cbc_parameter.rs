//! RFC 8018 B.2.3 RC2-CBC parameters.
//!
//! ```text
//! RC2-CBC-Parameter ::= SEQUENCE {
//!     rc2ParameterVersion INTEGER OPTIONAL,
//!     iv                  OCTET STRING (SIZE(8)) }
//! ```
//!
//! The version encodes the effective key bits; translating it is left to the
//! caller, as is the IV length.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// An optional parameter version and an IV.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
/// use tc_asn1_pkcs::Rc2CbcParameter;
///
/// let params = Rc2CbcParameter::new(Some(58.into()), Asn1OctetString::new(&[0; 8]))?;
/// assert_eq!(params.version().map(|v| v.as_bytes()), Some(&[58][..]));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Rc2CbcParameter {
    version: Option<Asn1Integer>,
    iv: Asn1OctetString,
}

impl Rc2CbcParameter {
    /// Rejects a negative version with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(version: Option<Asn1Integer>, iv: Asn1OctetString) -> Result<Self, Asn1Error> {
        if version.as_ref().is_some_and(Asn1Integer::is_negative) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { version, iv })
    }

    /// Returns the parameter version, if written.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Option<&Asn1Integer> {
        self.version.as_ref()
    }

    /// Returns the IV.
    /// Variable time: branches only on the encoding structure.
    pub fn iv(&self) -> &Asn1OctetString {
        &self.iv
    }
}

impl fmt::Display for Rc2CbcParameter {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(version) = &self.version {
            write!(f, "version {version}, ")?;
        }
        write!(f, "{} IV octets", self.iv.as_bytes().len())
    }
}

impl DecodeInner for Rc2CbcParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let version = fields.get_opt()?;
        let iv = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(version, iv)?))
    }
}

impl EncodeContent for Rc2CbcParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version.as_ref().map_or(0, |v| v.encoded_len(rules)) + self.iv.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(version) = &self.version {
            at += version.encode(rules, &mut out[at..])?;
        }
        at += self.iv.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Rc2CbcParameter {}

impl Tagged for Rc2CbcParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Rc2CbcParameter {}

impl Encode for Rc2CbcParameter {
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

    use super::Rc2CbcParameter;

    /// The parameters of `openssl pkcs8 -topk8 -v2 rc2-40-cbc`: version 160, 40 effective bits.
    const OPENSSL: [u8; 16] = [
        0x30, 0x0e, 0x02, 0x02, 0x00, 0xa0, 0x04, 0x08, 0x55, 0x94, 0x67, 0x8d, 0x2c, 0xa2, 0xd1,
        0x25,
    ];

    #[test]
    fn openssl_rc2_parameters_decode_and_encode_back() {
        let params = Rc2CbcParameter::decode_der(&OPENSSL, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(params.version().unwrap().as_bytes(), [0x00, 0xa0]);
        assert_eq!(
            params.iv().as_bytes(),
            [0x55, 0x94, 0x67, 0x8d, 0x2c, 0xa2, 0xd1, 0x25]
        );
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            OPENSSL
        );
        assert_eq!(params.to_string(), "version 160, 8 IV octets");
    }

    #[test]
    fn the_version_is_optional_but_never_negative() {
        let params = Rc2CbcParameter::new(None, Asn1OctetString::new(&[1; 8])).unwrap();
        let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire, [0x30, 10, 4, 8, 1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(
            Rc2CbcParameter::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
        assert_eq!(
            Rc2CbcParameter::new(Some((-1).into()), Asn1OctetString::new(&[1; 8])),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Rc2CbcParameter::decode_der(&[0x30, 0], &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
    }
}
