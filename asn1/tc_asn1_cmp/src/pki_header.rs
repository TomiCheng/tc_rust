//! RFC 4210 §5.1.1 `PKIHeader`, the header of a CMP message.
//!
//! ```text
//! PKIHeader ::= SEQUENCE {
//!     pvno          INTEGER { cmp1999(1), cmp2000(2) },
//!     sender        GeneralName,
//!     recipient     GeneralName,
//!     messageTime   [0] GeneralizedTime     OPTIONAL,
//!     protectionAlg [1] AlgorithmIdentifier OPTIONAL,
//!     senderKID     [2] KeyIdentifier       OPTIONAL,
//!     recipKID      [3] KeyIdentifier       OPTIONAL,
//!     transactionID [4] OCTET STRING        OPTIONAL,
//!     senderNonce   [5] OCTET STRING        OPTIONAL,
//!     recipNonce    [6] OCTET STRING        OPTIONAL,
//!     freeText      [7] PKIFreeText         OPTIONAL,
//!     generalInfo   [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1OctetString, Asn1Ref, Asn1SequenceOf,
    Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::name::GeneralName;

use crate::{InfoTypeAndValue, PkiFreeText};

/// The protocol version, who sends to whom, and the transaction's identifiers,
/// nonces and protection.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiHeader {
    pvno: Asn1Integer,
    sender: GeneralName,
    recipient: GeneralName,
    message_time: Option<Asn1GeneralizedTime>,
    protection_alg: Option<AlgorithmIdentifier>,
    sender_kid: Option<Asn1OctetString>,
    recip_kid: Option<Asn1OctetString>,
    transaction_id: Option<Asn1OctetString>,
    sender_nonce: Option<Asn1OctetString>,
    recip_nonce: Option<Asn1OctetString>,
    free_text: Option<PkiFreeText>,
    general_info: Option<Asn1SequenceOf<InfoTypeAndValue>>,
}

impl PkiHeader {
    /// The version, sender and recipient, with every option absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(pvno: Asn1Integer, sender: GeneralName, recipient: GeneralName) -> Self {
        Self {
            pvno,
            sender,
            recipient,
            message_time: None,
            protection_alg: None,
            sender_kid: None,
            recip_kid: None,
            transaction_id: None,
            sender_nonce: None,
            recip_nonce: None,
            free_text: None,
            general_info: None,
        }
    }

    /// Sets when the message was produced.
    /// Variable time: branches only on the encoding structure.
    pub fn with_message_time(mut self, message_time: Asn1GeneralizedTime) -> Self {
        self.message_time = Some(message_time);
        self
    }

    /// Sets the protection algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn with_protection_alg(mut self, protection_alg: AlgorithmIdentifier) -> Self {
        self.protection_alg = Some(protection_alg);
        self
    }

    /// Sets the sender's key identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_sender_kid(mut self, sender_kid: Asn1OctetString) -> Self {
        self.sender_kid = Some(sender_kid);
        self
    }

    /// Sets the recipient's key identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_recip_kid(mut self, recip_kid: Asn1OctetString) -> Self {
        self.recip_kid = Some(recip_kid);
        self
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

    /// Sets the nonce echoed from the recipient.
    /// Variable time: branches only on the encoding structure.
    pub fn with_recip_nonce(mut self, recip_nonce: Asn1OctetString) -> Self {
        self.recip_nonce = Some(recip_nonce);
        self
    }

    /// Sets text for a human.
    /// Variable time: branches only on the encoding structure.
    pub fn with_free_text(mut self, free_text: PkiFreeText) -> Self {
        self.free_text = Some(free_text);
        self
    }

    /// Sets the general information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_general_info(mut self, general_info: Vec<InfoTypeAndValue>) -> Self {
        self.general_info = Some(Asn1SequenceOf::new(general_info));
        self
    }

    /// Returns the protocol version: 1 cmp1999, 2 cmp2000, 3 cmp2021.
    /// Variable time: branches only on the encoding structure.
    pub fn pvno(&self) -> &Asn1Integer {
        &self.pvno
    }

    /// Returns the sender.
    /// Variable time: branches only on the encoding structure.
    pub fn sender(&self) -> &GeneralName {
        &self.sender
    }

    /// Returns the recipient.
    /// Variable time: branches only on the encoding structure.
    pub fn recipient(&self) -> &GeneralName {
        &self.recipient
    }

    /// Returns when the message was produced, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn message_time(&self) -> Option<&Asn1GeneralizedTime> {
        self.message_time.as_ref()
    }

    /// Returns the protection algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn protection_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.protection_alg.as_ref()
    }

    /// Returns the sender's key identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn sender_kid(&self) -> Option<&Asn1OctetString> {
        self.sender_kid.as_ref()
    }

    /// Returns the recipient's key identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn recip_kid(&self) -> Option<&Asn1OctetString> {
        self.recip_kid.as_ref()
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

    /// Returns the nonce echoed from the recipient, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn recip_nonce(&self) -> Option<&Asn1OctetString> {
        self.recip_nonce.as_ref()
    }

    /// Returns the text for a human, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn free_text(&self) -> Option<&PkiFreeText> {
        self.free_text.as_ref()
    }

    /// Returns the general information, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn general_info(&self) -> Option<&[InfoTypeAndValue]> {
        self.general_info.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for PkiHeader {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let pvno = fields.get()?;
        let sender = fields.get()?;
        let recipient = fields.get()?;
        let message_time = fields.get_explicit_opt::<Asn1GeneralizedTime>([0xa0])?;
        let protection_alg = fields.get_explicit_opt::<AlgorithmIdentifier>([0xa1])?;
        let sender_kid = fields.get_explicit_opt::<Asn1OctetString>([0xa2])?;
        let recip_kid = fields.get_explicit_opt::<Asn1OctetString>([0xa3])?;
        let transaction_id = fields.get_explicit_opt::<Asn1OctetString>([0xa4])?;
        let sender_nonce = fields.get_explicit_opt::<Asn1OctetString>([0xa5])?;
        let recip_nonce = fields.get_explicit_opt::<Asn1OctetString>([0xa6])?;
        let free_text = fields.get_explicit_opt::<PkiFreeText>([0xa7])?;
        let general_info = fields.get_explicit_opt::<Asn1SequenceOf<InfoTypeAndValue>>([0xa8])?;
        fields.end()?;
        let value = Self {
            pvno,
            sender,
            recipient,
            message_time,
            protection_alg,
            sender_kid,
            recip_kid,
            transaction_id,
            sender_nonce,
            recip_nonce,
            free_text,
            general_info,
        };
        Ok(value)
    }
}

impl DecodeInner for PkiHeader {
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

impl EncodeContent for PkiHeader {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.pvno.encoded_len(rules)
            + self.sender.encoded_len(rules)
            + self.recipient.encoded_len(rules)
            + self
                .message_time
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .protection_alg
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .sender_kid
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
            + self
                .recip_kid
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa3], v).encoded_len(rules))
            + self
                .transaction_id
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa4], v).encoded_len(rules))
            + self
                .sender_nonce
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa5], v).encoded_len(rules))
            + self
                .recip_nonce
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa6], v).encoded_len(rules))
            + self
                .free_text
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa7], v).encoded_len(rules))
            + self
                .general_info
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa8], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.pvno.encode(rules, out)?;
        at += self.sender.encode(rules, &mut out[at..])?;
        at += self.recipient.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.message_time {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.protection_alg {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.sender_kid {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.recip_kid {
            at += Explicit::new(&[0xa3], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.transaction_id {
            at += Explicit::new(&[0xa4], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.sender_nonce {
            at += Explicit::new(&[0xa5], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.recip_nonce {
            at += Explicit::new(&[0xa6], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.free_text {
            at += Explicit::new(&[0xa7], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.general_info {
            at += Explicit::new(&[0xa8], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PkiHeader {}

impl Tagged for PkiHeader {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiHeader {}

impl Encode for PkiHeader {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
