//! RFC 4210 §5.1.3.1 `PBMParameter`, the parameters of a password-based MAC.
//!
//! ```text
//! PBMParameter ::= SEQUENCE {
//!     salt           OCTET STRING,
//!     owf            AlgorithmIdentifier,
//!     iterationCount INTEGER,
//!     mac            AlgorithmIdentifier }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The salt, one-way function, iteration count and MAC of `passwordBasedMac`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PbmParameter {
    salt: Asn1OctetString,
    owf: AlgorithmIdentifier,
    iteration_count: Asn1Integer,
    mac: AlgorithmIdentifier,
}

impl PbmParameter {
    /// Every parameter.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        salt: Asn1OctetString,
        owf: AlgorithmIdentifier,
        iteration_count: Asn1Integer,
        mac: AlgorithmIdentifier,
    ) -> Self {
        Self {
            salt,
            owf,
            iteration_count,
            mac,
        }
    }

    /// Returns the salt.
    /// Variable time: branches only on the encoding structure.
    pub fn salt(&self) -> &Asn1OctetString {
        &self.salt
    }

    /// Returns the one-way function, a hash.
    /// Variable time: branches only on the encoding structure.
    pub fn owf(&self) -> &AlgorithmIdentifier {
        &self.owf
    }

    /// Returns how many times the hash is applied.
    /// Variable time: branches only on the encoding structure.
    pub fn iteration_count(&self) -> &Asn1Integer {
        &self.iteration_count
    }

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &AlgorithmIdentifier {
        &self.mac
    }
}

impl DecodeContent for PbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let salt = fields.get()?;
        let owf = fields.get()?;
        let iteration_count = fields.get()?;
        let mac = fields.get()?;
        fields.end()?;
        let value = Self {
            salt,
            owf,
            iteration_count,
            mac,
        };
        Ok(value)
    }
}

impl DecodeInner for PbmParameter {
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

impl EncodeContent for PbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.salt.encoded_len(rules)
            + self.owf.encoded_len(rules)
            + self.iteration_count.encoded_len(rules)
            + self.mac.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.salt.encode(rules, out)?;
        at += self.owf.encode(rules, &mut out[at..])?;
        at += self.iteration_count.encode(rules, &mut out[at..])?;
        at += self.mac.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PbmParameter {}

impl Tagged for PbmParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PbmParameter {}

impl Encode for PbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
