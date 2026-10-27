//! RFC 5652 §10.2.4 `IssuerAndSerialNumber`, which names a certificate by its
//! issuer and serial number.
//!
//! ```text
//! IssuerAndSerialNumber ::= SEQUENCE {
//!     issuer Name,
//!     serialNumber CertificateSerialNumber }
//! CertificateSerialNumber ::= INTEGER
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Name;
use tc_asn1_x509::cert::Certificate;

/// A certificate named by its issuer and serial number.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::signed::IssuerAndSerialNumber;
///
/// let id = IssuerAndSerialNumber::new("CN=Example CA".parse()?, 4660.into());
/// let der = id.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(IssuerAndSerialNumber::decode_der(&der, &DecodingOptions::default())?.1, id);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IssuerAndSerialNumber {
    issuer: Name,
    serial_number: Asn1Integer,
}

impl IssuerAndSerialNumber {
    /// Stores the issuer and serial number without checking them.
    /// Variable time: branches only on the encoding structure.
    pub fn new(issuer: Name, serial_number: Asn1Integer) -> Self {
        Self {
            issuer,
            serial_number,
        }
    }

    /// Copies the issuer and serial number of `certificate`.
    /// Variable time: branches only on the encoding structure.
    pub fn of(certificate: &Certificate) -> Self {
        Self::new(
            certificate.issuer().clone(),
            certificate.serial_number().clone(),
        )
    }

    /// Returns the issuer.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Returns the serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }
}

impl DecodeContent for IssuerAndSerialNumber {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let issuer = fields.get()?;
        let serial_number = fields.get()?;
        fields.end()?;
        Ok(Self::new(issuer, serial_number))
    }
}

impl DecodeInner for IssuerAndSerialNumber {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for IssuerAndSerialNumber {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer.encoded_len(rules) + self.serial_number.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.issuer.encode(rules, out)?;
        Ok(at + self.serial_number.encode(rules, &mut out[at..])?)
    }
}

impl Decode for IssuerAndSerialNumber {}

impl Tagged for IssuerAndSerialNumber {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for IssuerAndSerialNumber {}

impl Encode for IssuerAndSerialNumber {
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

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::cert::Certificate;

    use super::IssuerAndSerialNumber;

    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    #[test]
    fn a_certificate_is_named_by_its_issuer_and_serial_number() {
        let certificate = Certificate::decode(RFC_8410, &DecodingOptions::default())
            .unwrap()
            .1;
        let id = IssuerAndSerialNumber::of(&certificate);
        assert_eq!(id.issuer().to_string(), "CN=IETF Test Demo");
        assert_eq!(id.serial_number(), certificate.serial_number());
        let der = id.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            IssuerAndSerialNumber::decode_der(&der, &DecodingOptions::default())
                .unwrap()
                .1,
            id
        );
    }

    #[test]
    fn a_missing_serial_number_or_swapped_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x02\x30\x00"[..], Asn1Error::Truncated),
            (
                &b"\x30\x05\x02\x01\x01\x30\x00"[..],
                Asn1Error::UnexpectedTag,
            ),
        ] {
            assert_eq!(
                IssuerAndSerialNumber::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
