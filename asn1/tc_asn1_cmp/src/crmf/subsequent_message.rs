//! RFC 4211 §4.2 `SubsequentMessage`, how possession will be proven later.
//!
//! ```text
//! SubsequentMessage ::= INTEGER {
//!     encrCert      (0),
//!     challengeResp (1) }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// An encrypted certificate to decrypt, or a challenge to answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SubsequentMessage {
    /// `encrCert (0)`: the CA returns the certificate encrypted for the key.
    EncrCert = 0,
    /// `challengeResp (1)`: the CA sends a challenge to decrypt.
    ChallengeResp = 1,
}

impl SubsequentMessage {
    /// Returns the INTEGER value.
    /// Variable time: branches only on the encoding structure.
    pub fn number(self) -> u8 {
        self as u8
    }
}

impl DecodeContent for SubsequentMessage {
    /// Values other than 0 and 1 are `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let number = Asn1Integer::decode_content(value, context)?;
        match u8::try_from(&number) {
            Ok(0) => Ok(Self::EncrCert),
            Ok(1) => Ok(Self::ChallengeResp),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl DecodeInner for SubsequentMessage {
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

impl EncodeContent for SubsequentMessage {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        1
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, _rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        *out.first_mut().ok_or(Asn1Error::BufferTooSmall)? = self.number();
        Ok(1)
    }
}

impl Decode for SubsequentMessage {}

impl Tagged for SubsequentMessage {
    const TAG: &'static [u8] = tag::INTEGER;
}

impl EncodeTagged for SubsequentMessage {}

impl Encode for SubsequentMessage {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
