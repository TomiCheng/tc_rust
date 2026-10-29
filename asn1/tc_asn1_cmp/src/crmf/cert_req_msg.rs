//! RFC 4211 §3 `CertReqMsg`, one request with its proof of possession.
//!
//! ```text
//! CertReqMsg ::= SEQUENCE {
//!     certReq CertRequest,
//!     popo    ProofOfPossession OPTIONAL,
//!     regInfo SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::{AttributeTypeAndValue, CertRequest, ProofOfPossession};

/// The request, the proof of possession, and registration information.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertReqMsg {
    cert_req: CertRequest,
    popo: Option<ProofOfPossession>,
    reg_info: Option<Asn1SequenceOf<AttributeTypeAndValue>>,
}

impl CertReqMsg {
    /// The request, without proof of possession or registration information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_req: CertRequest) -> Self {
        Self {
            cert_req,
            popo: None,
            reg_info: None,
        }
    }

    /// Sets the proof of possession.
    /// Variable time: branches only on the encoding structure.
    pub fn with_popo(mut self, popo: ProofOfPossession) -> Self {
        self.popo = Some(popo);
        self
    }

    /// Sets the registration information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_reg_info(mut self, reg_info: Vec<AttributeTypeAndValue>) -> Self {
        self.reg_info = Some(Asn1SequenceOf::new(reg_info));
        self
    }

    /// Returns the request.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req(&self) -> &CertRequest {
        &self.cert_req
    }

    /// Returns the proof of possession, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn popo(&self) -> Option<&ProofOfPossession> {
        self.popo.as_ref()
    }

    /// Returns the registration information, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn reg_info(&self) -> Option<&[AttributeTypeAndValue]> {
        self.reg_info.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for CertReqMsg {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_req = fields.get()?;
        let popo = match fields.peek() {
            Some(Ok(element)) if matches!(element.tag(), [0x80] | [0xa1] | [0xa2] | [0xa3]) => {
                Some(fields.get()?)
            }
            Some(Err(error)) => return Err(error),
            _ => None,
        };
        let reg_info = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_req,
            popo,
            reg_info,
        };
        Ok(value)
    }
}

impl DecodeInner for CertReqMsg {
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

impl EncodeContent for CertReqMsg {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_req.encoded_len(rules)
            + self.popo.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.reg_info.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_req.encode(rules, out)?;
        if let Some(v) = &self.popo {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.reg_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertReqMsg {}

impl Tagged for CertReqMsg {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertReqMsg {}

impl Encode for CertReqMsg {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
