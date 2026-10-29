//! RFC 4210 §5.2.8 `Challenge`, a proof-of-possession challenge for an
//! encryption key.
//!
//! ```text
//! Challenge ::= SEQUENCE {
//!     owf       AlgorithmIdentifier OPTIONAL,
//!     witness   OCTET STRING,
//!     challenge OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A hash of a random integer, and a `Rand` encrypted for the key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Challenge {
    owf: Option<AlgorithmIdentifier>,
    witness: Asn1OctetString,
    challenge: Asn1OctetString,
}

impl Challenge {
    /// The witness and challenge, without a one-way function.
    /// Variable time: branches only on the encoding structure.
    pub fn new(witness: Asn1OctetString, challenge: Asn1OctetString) -> Self {
        Self {
            owf: None,
            witness,
            challenge,
        }
    }

    /// Sets the one-way function; the first challenge must carry it.
    /// Variable time: branches only on the encoding structure.
    pub fn with_owf(mut self, owf: AlgorithmIdentifier) -> Self {
        self.owf = Some(owf);
        self
    }

    /// Returns the one-way function, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn owf(&self) -> Option<&AlgorithmIdentifier> {
        self.owf.as_ref()
    }

    /// Returns the hash of the random integer.
    /// Variable time: branches only on the encoding structure.
    pub fn witness(&self) -> &Asn1OctetString {
        &self.witness
    }

    /// Returns the encrypted `Rand`.
    /// Variable time: branches only on the encoding structure.
    pub fn challenge(&self) -> &Asn1OctetString {
        &self.challenge
    }
}

impl DecodeContent for Challenge {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let owf = fields.get_opt()?;
        let witness = fields.get()?;
        let challenge = fields.get()?;
        fields.end()?;
        let value = Self {
            owf,
            witness,
            challenge,
        };
        Ok(value)
    }
}

impl DecodeInner for Challenge {
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

impl EncodeContent for Challenge {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.owf.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.witness.encoded_len(rules)
            + self.challenge.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.owf {
            at += v.encode(rules, &mut out[at..])?;
        }
        at += self.witness.encode(rules, &mut out[at..])?;
        at += self.challenge.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Challenge {}

impl Tagged for Challenge {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Challenge {}

impl Encode for Challenge {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
