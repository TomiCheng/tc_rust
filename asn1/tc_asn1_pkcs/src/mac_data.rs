//! RFC 7292 §4 `MacData`, the MAC of PKCS #12 password integrity mode.
//!
//! ```text
//! MacData ::= SEQUENCE {
//!     mac        DigestInfo,
//!     macSalt    OCTET STRING,
//!     iterations INTEGER DEFAULT 1 }
//! ```
//!
//! A written default iteration count is accepted under BER and rejected under
//! DER; encoding omits it.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::DigestInfo;

/// The MAC as a digest algorithm and value, its salt and its iteration count.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_pkcs::MacData;
/// use tc_asn1_x509::alg::{AlgorithmIdentifier, DigestInfo};
///
/// let sha256 = AlgorithmIdentifier::with_null("2.16.840.1.101.3.4.2.1".parse()?);
/// let mac = DigestInfo::new(sha256, &[0x5a; 32]);
/// let data = MacData::new(mac, Asn1OctetString::new(&[1; 8])).with_iterations(2048.into());
///
/// let der = data.encode_to_vec(&EncodingOptions::DER)?;
/// let back = MacData::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(back.iterations(), &2048.into());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MacData {
    mac: DigestInfo,
    mac_salt: Asn1OctetString,
    iterations: Asn1Integer,
}

impl MacData {
    /// The MAC and its salt, with the default iteration count of 1.
    /// Variable time: branches only on the encoding structure.
    pub fn new(mac: DigestInfo, mac_salt: Asn1OctetString) -> Self {
        Self {
            mac,
            mac_salt,
            iterations: 1.into(),
        }
    }

    /// Sets the iteration count of the MAC key derivation.
    /// Variable time: branches only on the encoding structure.
    pub fn with_iterations(mut self, iterations: Asn1Integer) -> Self {
        self.iterations = iterations;
        self
    }

    /// Returns the MAC: its digest algorithm and value.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &DigestInfo {
        &self.mac
    }

    /// Returns the salt of the MAC key derivation.
    /// Variable time: branches only on the encoding structure.
    pub fn mac_salt(&self) -> &Asn1OctetString {
        &self.mac_salt
    }

    /// Returns the iteration count, 1 when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn iterations(&self) -> &Asn1Integer {
        &self.iterations
    }

    fn writes_iterations(&self) -> bool {
        self.iterations != Asn1Integer::from(1)
    }
}

impl DecodeContent for MacData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let mac = fields.get()?;
        let mac_salt = fields.get()?;
        let iterations = fields.get_default(Asn1Integer::from(1))?;
        fields.end()?;
        Ok(Self {
            mac,
            mac_salt,
            iterations,
        })
    }
}

impl DecodeInner for MacData {
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

impl EncodeContent for MacData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = self.mac.encoded_len(rules) + self.mac_salt.encoded_len(rules);
        if self.writes_iterations() {
            len += self.iterations.encoded_len(rules);
        }
        len
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.mac.encode(rules, out)?;
        at += self.mac_salt.encode(rules, &mut out[at..])?;
        if self.writes_iterations() {
            at += self.iterations.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for MacData {}

impl Tagged for MacData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MacData {}

impl Encode for MacData {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
