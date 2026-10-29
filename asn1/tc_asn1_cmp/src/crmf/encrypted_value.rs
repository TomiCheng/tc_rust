//! RFC 4211 §4.2.1 `EncryptedValue`, an encrypted value, deprecated in favour of
//! `EnvelopedData`.
//!
//! ```text
//! EncryptedValue ::= SEQUENCE {
//!     intendedAlg [0] AlgorithmIdentifier OPTIONAL,
//!     symmAlg     [1] AlgorithmIdentifier OPTIONAL,
//!     encSymmKey  [2] BIT STRING          OPTIONAL,
//!     keyAlg      [3] AlgorithmIdentifier OPTIONAL,
//!     valueHint   [4] OCTET STRING        OPTIONAL,
//!     encValue        BIT STRING }
//! ```
//!
//! The module uses implicit tags.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
    Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A value encrypted under a symmetric key, and that key encrypted for the
/// recipient.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncryptedValue {
    intended_alg: Option<AlgorithmIdentifier>,
    symm_alg: Option<AlgorithmIdentifier>,
    enc_symm_key: Option<Asn1BitString>,
    key_alg: Option<AlgorithmIdentifier>,
    value_hint: Option<Asn1OctetString>,
    enc_value: Asn1BitString,
}

impl EncryptedValue {
    /// The encrypted value, with every other field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(enc_value: Asn1BitString) -> Self {
        Self {
            intended_alg: None,
            symm_alg: None,
            enc_symm_key: None,
            key_alg: None,
            value_hint: None,
            enc_value,
        }
    }

    /// Sets the algorithm the value is for.
    /// Variable time: branches only on the encoding structure.
    pub fn with_intended_alg(mut self, intended_alg: AlgorithmIdentifier) -> Self {
        self.intended_alg = Some(intended_alg);
        self
    }

    /// Sets the symmetric algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn with_symm_alg(mut self, symm_alg: AlgorithmIdentifier) -> Self {
        self.symm_alg = Some(symm_alg);
        self
    }

    /// Sets the encrypted symmetric key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_enc_symm_key(mut self, enc_symm_key: Asn1BitString) -> Self {
        self.enc_symm_key = Some(enc_symm_key);
        self
    }

    /// Sets the algorithm that encrypted the key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_alg(mut self, key_alg: AlgorithmIdentifier) -> Self {
        self.key_alg = Some(key_alg);
        self
    }

    /// Sets a hint for the sender.
    /// Variable time: branches only on the encoding structure.
    pub fn with_value_hint(mut self, value_hint: Asn1OctetString) -> Self {
        self.value_hint = Some(value_hint);
        self
    }

    /// Returns the algorithm the value is for, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn intended_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.intended_alg.as_ref()
    }

    /// Returns the symmetric algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn symm_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.symm_alg.as_ref()
    }

    /// Returns the encrypted symmetric key, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn enc_symm_key(&self) -> Option<&Asn1BitString> {
        self.enc_symm_key.as_ref()
    }

    /// Returns the algorithm that encrypted the key, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.key_alg.as_ref()
    }

    /// Returns the hint, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn value_hint(&self) -> Option<&Asn1OctetString> {
        self.value_hint.as_ref()
    }

    /// Returns the encrypted value.
    /// Variable time: branches only on the encoding structure.
    pub fn enc_value(&self) -> &Asn1BitString {
        &self.enc_value
    }
}

impl DecodeContent for EncryptedValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let intended_alg = fields.get_implicit_opt([0xa0])?;
        let symm_alg = fields.get_implicit_opt([0xa1])?;
        let enc_symm_key = fields.get_implicit_opt([0x82])?;
        let key_alg = fields.get_implicit_opt([0xa3])?;
        let value_hint = fields.get_implicit_opt([0x84])?;
        let enc_value = fields.get()?;
        fields.end()?;
        let value = Self {
            intended_alg,
            symm_alg,
            enc_symm_key,
            key_alg,
            value_hint,
            enc_value,
        };
        Ok(value)
    }
}

impl DecodeInner for EncryptedValue {
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

impl EncodeContent for EncryptedValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.intended_alg
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .symm_alg
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .enc_symm_key
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x82], v).encoded_len(rules))
            + self
                .key_alg
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa3], v).encoded_len(rules))
            + self
                .value_hint
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x84], v).encoded_len(rules))
            + self.enc_value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.intended_alg {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.symm_alg {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.enc_symm_key {
            at += Implicit::new(&[0x82], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.key_alg {
            at += Implicit::new(&[0xa3], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.value_hint {
            at += Implicit::new(&[0x84], v).encode(rules, &mut out[at..])?;
        }
        at += self.enc_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EncryptedValue {}

impl Tagged for EncryptedValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncryptedValue {}

impl Encode for EncryptedValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
