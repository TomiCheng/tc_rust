//! RFC 9810 §5.1.3.4 `KemOtherInfo`, the context bound into a KEM-based MAC key.
//!
//! ```text
//! KemOtherInfo ::= SEQUENCE {
//!     staticString  PKIFreeText,  -- MUST be "CMP-KEM"
//!     transactionID [0] OCTET STRING OPTIONAL,
//!     senderNonce   [1] OCTET STRING OPTIONAL,
//!     recipNonce    [2] OCTET STRING OPTIONAL,
//!     len           INTEGER (1..MAX),
//!     mac           AlgorithmIdentifier{MAC-ALGORITHM, {...}},
//!     ct            OCTET STRING }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::PkiFreeText;

/// The transaction, the key length and MAC, and the ciphertext the key came from.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KemOtherInfo {
    static_string: PkiFreeText,
    transaction_id: Option<Asn1OctetString>,
    sender_nonce: Option<Asn1OctetString>,
    recip_nonce: Option<Asn1OctetString>,
    len: Asn1Integer,
    mac: AlgorithmIdentifier,
    ct: Asn1OctetString,
}

impl KemOtherInfo {
    /// The required fields, without the transaction identifier or nonces.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        static_string: PkiFreeText,
        len: Asn1Integer,
        mac: AlgorithmIdentifier,
        ct: Asn1OctetString,
    ) -> Self {
        Self {
            static_string,
            transaction_id: None,
            sender_nonce: None,
            recip_nonce: None,
            len,
            mac,
            ct,
        }
    }

    /// Sets the transaction identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_transaction_id(mut self, transaction_id: Asn1OctetString) -> Self {
        self.transaction_id = Some(transaction_id);
        self
    }

    /// Sets the sender's nonce.
    /// Variable time: branches only on the encoding structure.
    pub fn with_sender_nonce(mut self, sender_nonce: Asn1OctetString) -> Self {
        self.sender_nonce = Some(sender_nonce);
        self
    }

    /// Sets the recipient's nonce.
    /// Variable time: branches only on the encoding structure.
    pub fn with_recip_nonce(mut self, recip_nonce: Asn1OctetString) -> Self {
        self.recip_nonce = Some(recip_nonce);
        self
    }

    /// Returns the static string, "CMP-KEM".
    /// Variable time: branches only on the encoding structure.
    pub fn static_string(&self) -> &PkiFreeText {
        &self.static_string
    }

    /// Returns the transaction identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn transaction_id(&self) -> Option<&Asn1OctetString> {
        self.transaction_id.as_ref()
    }

    /// Returns the sender's nonce, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn sender_nonce(&self) -> Option<&Asn1OctetString> {
        self.sender_nonce.as_ref()
    }

    /// Returns the recipient's nonce, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn recip_nonce(&self) -> Option<&Asn1OctetString> {
        self.recip_nonce.as_ref()
    }

    /// Returns the length of the MAC key in octets.
    /// Variable time: branches only on the encoding structure.
    pub fn len(&self) -> &Asn1Integer {
        &self.len
    }

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &AlgorithmIdentifier {
        &self.mac
    }

    /// Returns the KEM ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn ct(&self) -> &Asn1OctetString {
        &self.ct
    }
}

impl DecodeContent for KemOtherInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let static_string = fields.get()?;
        let transaction_id = fields.get_explicit_opt::<Asn1OctetString>([0xa0])?;
        let sender_nonce = fields.get_explicit_opt::<Asn1OctetString>([0xa1])?;
        let recip_nonce = fields.get_explicit_opt::<Asn1OctetString>([0xa2])?;
        let len = fields.get()?;
        let mac = fields.get()?;
        let ct = fields.get()?;
        fields.end()?;
        let value = Self {
            static_string,
            transaction_id,
            sender_nonce,
            recip_nonce,
            len,
            mac,
            ct,
        };
        Ok(value)
    }
}

impl DecodeInner for KemOtherInfo {
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

impl EncodeContent for KemOtherInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.static_string.encoded_len(rules)
            + self
                .transaction_id
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .sender_nonce
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .recip_nonce
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
            + self.len.encoded_len(rules)
            + self.mac.encoded_len(rules)
            + self.ct.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.static_string.encode(rules, out)?;
        if let Some(v) = &self.transaction_id {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.sender_nonce {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.recip_nonce {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        at += self.len.encode(rules, &mut out[at..])?;
        at += self.mac.encode(rules, &mut out[at..])?;
        at += self.ct.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KemOtherInfo {}

impl Tagged for KemOtherInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KemOtherInfo {}

impl Encode for KemOtherInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
