//! RFC 4211 §4.1 `POPOSigningKeyInput`, what a signature proof of possession signs
//! when the template lacks the subject or key.
//!
//! ```text
//! POPOSigningKeyInput ::= SEQUENCE {
//!     authInfo  CHOICE {
//!         sender       [0] GeneralName,
//!         publicKeyMAC PKMACValue },
//!     publicKey SubjectPublicKeyInfo }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::crmf::AuthInfo;

/// The sender or a MAC, and the public key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PopoSigningKeyInput {
    auth_info: AuthInfo,
    public_key: SubjectPublicKeyInfo,
}

impl PopoSigningKeyInput {
    /// The sender and the public key.
    /// Variable time: branches only on the encoding structure.
    pub fn new(auth_info: AuthInfo, public_key: SubjectPublicKeyInfo) -> Self {
        Self {
            auth_info,
            public_key,
        }
    }

    /// Returns the sender or MAC.
    /// Variable time: branches only on the encoding structure.
    pub fn auth_info(&self) -> &AuthInfo {
        &self.auth_info
    }

    /// Returns the public key.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key(&self) -> &SubjectPublicKeyInfo {
        &self.public_key
    }
}

impl DecodeContent for PopoSigningKeyInput {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let auth_info = fields.get()?;
        let public_key = fields.get()?;
        fields.end()?;
        let value = Self {
            auth_info,
            public_key,
        };
        Ok(value)
    }
}

impl DecodeInner for PopoSigningKeyInput {
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

impl EncodeContent for PopoSigningKeyInput {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.auth_info.encoded_len(rules) + self.public_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.auth_info.encode(rules, out)?;
        at += self.public_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PopoSigningKeyInput {}

impl Tagged for PopoSigningKeyInput {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PopoSigningKeyInput {}

impl Encode for PopoSigningKeyInput {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
