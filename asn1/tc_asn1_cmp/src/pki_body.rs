//! RFC 4210 §5.1.2 `PKIBody`, the message-specific part of a CMP message.
//!
//! ```text
//! PKIBody ::= CHOICE {
//!     ir       [0]  CertReqMessages,
//!     ip       [1]  CertRepMessage,
//!     cr       [2]  CertReqMessages,
//!     cp       [3]  CertRepMessage,
//!     p10cr    [4]  CertificationRequest,
//!     popdecc  [5]  POPODecKeyChallContent,
//!     popdecr  [6]  POPODecKeyRespContent,
//!     kur      [7]  CertReqMessages,
//!     kup      [8]  CertRepMessage,
//!     krr      [9]  CertReqMessages,
//!     krp      [10] KeyRecRepContent,
//!     rr       [11] RevReqContent,
//!     rp       [12] RevRepContent,
//!     ccr      [13] CertReqMessages,
//!     ccp      [14] CertRepMessage,
//!     ckuann   [15] CAKeyUpdAnnContent,
//!     cann     [16] CertAnnContent,
//!     rann     [17] RevAnnContent,
//!     crlann   [18] CRLAnnContent,
//!     pkiconf  [19] PKIConfirmContent,
//!     nested   [20] NestedMessageContent,
//!     genm     [21] GenMsgContent,
//!     genp     [22] GenRepContent,
//!     error    [23] ErrorMsgContent,
//!     certConf [24] CertConfirmContent,
//!     pollReq  [25] PollReqContent,
//!     pollRep  [26] PollRepContent }
//! PKIConfirmContent ::= NULL
//! ```
//!
//! The module uses explicit tags. `CertAnnContent` is a `CmpCertificate` and
//! `NestedMessageContent` is `PKIMessages`.

use tc_asn1::{
    Asn1Error, Asn1Null, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Explicit,
};
use tc_asn1_pkcs::CertificationRequest;

use crate::crmf::CertReqMessages;
use crate::{
    CaKeyUpdAnnContent, CertConfirmContent, CertRepMessage, CmpCertificate, CrlAnnContent,
    ErrorMsgContent, GenMsgContent, GenRepContent, KeyRecRepContent, PkiMessages, PollRepContent,
    PollReqContent, PopoDecKeyChallContent, PopoDecKeyRespContent, RevAnnContent, RevRepContent,
    RevReqContent,
};

/// One of the 27 CMP message bodies.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum PkiBody {
    /// `[0]`, Initialization Request.
    Ir(CertReqMessages),
    /// `[1]`, Initialization Response.
    Ip(CertRepMessage),
    /// `[2]`, Certification Request.
    Cr(CertReqMessages),
    /// `[3]`, Certification Response.
    Cp(CertRepMessage),
    /// `[4]`, PKCS #10 Certification Request.
    P10cr(CertificationRequest),
    /// `[5]`, POP Challenge.
    Popdecc(PopoDecKeyChallContent),
    /// `[6]`, POP Response.
    Popdecr(PopoDecKeyRespContent),
    /// `[7]`, Key Update Request.
    Kur(CertReqMessages),
    /// `[8]`, Key Update Response.
    Kup(CertRepMessage),
    /// `[9]`, Key Recovery Request.
    Krr(CertReqMessages),
    /// `[10]`, Key Recovery Response.
    Krp(KeyRecRepContent),
    /// `[11]`, Revocation Request.
    Rr(RevReqContent),
    /// `[12]`, Revocation Response.
    Rp(RevRepContent),
    /// `[13]`, Cross-Certification Request.
    Ccr(CertReqMessages),
    /// `[14]`, Cross-Certification Response.
    Ccp(CertRepMessage),
    /// `[15]`, CA Key Update Announcement.
    Ckuann(CaKeyUpdAnnContent),
    /// `[16]`, Certificate Announcement.
    Cann(CmpCertificate),
    /// `[17]`, Revocation Announcement.
    Rann(RevAnnContent),
    /// `[18]`, CRL Announcement.
    Crlann(CrlAnnContent),
    /// `[19]`, Confirmation.
    Pkiconf,
    /// `[20]`, Nested Message.
    Nested(PkiMessages),
    /// `[21]`, General Message.
    Genm(GenMsgContent),
    /// `[22]`, General Response.
    Genp(GenRepContent),
    /// `[23]`, Error Message.
    Error(ErrorMsgContent),
    /// `[24]`, Certificate Confirmation.
    CertConf(CertConfirmContent),
    /// `[25]`, Polling Request.
    PollReq(PollReqContent),
    /// `[26]`, Polling Response.
    PollRep(PollRepContent),
}

impl DecodeInner for PkiBody {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// A NULL alternative with contents is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xa0] => {
                let mut inner = element.children(context)?;
                let value = Self::Ir(inner.get()?);
                inner.end()?;
                value
            }
            [0xa1] => {
                let mut inner = element.children(context)?;
                let value = Self::Ip(inner.get()?);
                inner.end()?;
                value
            }
            [0xa2] => {
                let mut inner = element.children(context)?;
                let value = Self::Cr(inner.get()?);
                inner.end()?;
                value
            }
            [0xa3] => {
                let mut inner = element.children(context)?;
                let value = Self::Cp(inner.get()?);
                inner.end()?;
                value
            }
            [0xa4] => {
                let mut inner = element.children(context)?;
                let value = Self::P10cr(inner.get()?);
                inner.end()?;
                value
            }
            [0xa5] => {
                let mut inner = element.children(context)?;
                let value = Self::Popdecc(inner.get()?);
                inner.end()?;
                value
            }
            [0xa6] => {
                let mut inner = element.children(context)?;
                let value = Self::Popdecr(inner.get()?);
                inner.end()?;
                value
            }
            [0xa7] => {
                let mut inner = element.children(context)?;
                let value = Self::Kur(inner.get()?);
                inner.end()?;
                value
            }
            [0xa8] => {
                let mut inner = element.children(context)?;
                let value = Self::Kup(inner.get()?);
                inner.end()?;
                value
            }
            [0xa9] => {
                let mut inner = element.children(context)?;
                let value = Self::Krr(inner.get()?);
                inner.end()?;
                value
            }
            [0xaa] => {
                let mut inner = element.children(context)?;
                let value = Self::Krp(inner.get()?);
                inner.end()?;
                value
            }
            [0xab] => {
                let mut inner = element.children(context)?;
                let value = Self::Rr(inner.get()?);
                inner.end()?;
                value
            }
            [0xac] => {
                let mut inner = element.children(context)?;
                let value = Self::Rp(inner.get()?);
                inner.end()?;
                value
            }
            [0xad] => {
                let mut inner = element.children(context)?;
                let value = Self::Ccr(inner.get()?);
                inner.end()?;
                value
            }
            [0xae] => {
                let mut inner = element.children(context)?;
                let value = Self::Ccp(inner.get()?);
                inner.end()?;
                value
            }
            [0xaf] => {
                let mut inner = element.children(context)?;
                let value = Self::Ckuann(inner.get()?);
                inner.end()?;
                value
            }
            [0xb0] => {
                let mut inner = element.children(context)?;
                let value = Self::Cann(inner.get()?);
                inner.end()?;
                value
            }
            [0xb1] => {
                let mut inner = element.children(context)?;
                let value = Self::Rann(inner.get()?);
                inner.end()?;
                value
            }
            [0xb2] => {
                let mut inner = element.children(context)?;
                let value = Self::Crlann(inner.get()?);
                inner.end()?;
                value
            }
            [0xb3] => {
                let mut inner = element.children(context)?;
                inner.get::<Asn1Null>()?;
                inner.end()?;
                Self::Pkiconf
            }
            [0xb4] => {
                let mut inner = element.children(context)?;
                let value = Self::Nested(inner.get()?);
                inner.end()?;
                value
            }
            [0xb5] => {
                let mut inner = element.children(context)?;
                let value = Self::Genm(inner.get()?);
                inner.end()?;
                value
            }
            [0xb6] => {
                let mut inner = element.children(context)?;
                let value = Self::Genp(inner.get()?);
                inner.end()?;
                value
            }
            [0xb7] => {
                let mut inner = element.children(context)?;
                let value = Self::Error(inner.get()?);
                inner.end()?;
                value
            }
            [0xb8] => {
                let mut inner = element.children(context)?;
                let value = Self::CertConf(inner.get()?);
                inner.end()?;
                value
            }
            [0xb9] => {
                let mut inner = element.children(context)?;
                let value = Self::PollReq(inner.get()?);
                inner.end()?;
                value
            }
            [0xba] => {
                let mut inner = element.children(context)?;
                let value = Self::PollRep(inner.get()?);
                inner.end()?;
                value
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for PkiBody {}

impl EncodeContent for PkiBody {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Ir(inner) => inner.encoded_len(rules),
            Self::Ip(inner) => inner.encoded_len(rules),
            Self::Cr(inner) => inner.encoded_len(rules),
            Self::Cp(inner) => inner.encoded_len(rules),
            Self::P10cr(inner) => inner.encoded_len(rules),
            Self::Popdecc(inner) => inner.encoded_len(rules),
            Self::Popdecr(inner) => inner.encoded_len(rules),
            Self::Kur(inner) => inner.encoded_len(rules),
            Self::Kup(inner) => inner.encoded_len(rules),
            Self::Krr(inner) => inner.encoded_len(rules),
            Self::Krp(inner) => inner.encoded_len(rules),
            Self::Rr(inner) => inner.encoded_len(rules),
            Self::Rp(inner) => inner.encoded_len(rules),
            Self::Ccr(inner) => inner.encoded_len(rules),
            Self::Ccp(inner) => inner.encoded_len(rules),
            Self::Ckuann(inner) => inner.encoded_len(rules),
            Self::Cann(inner) => inner.encoded_len(rules),
            Self::Rann(inner) => inner.encoded_len(rules),
            Self::Crlann(inner) => inner.encoded_len(rules),
            Self::Pkiconf => Asn1Null.encoded_len(rules),
            Self::Nested(inner) => inner.encoded_len(rules),
            Self::Genm(inner) => inner.encoded_len(rules),
            Self::Genp(inner) => inner.encoded_len(rules),
            Self::Error(inner) => inner.encoded_len(rules),
            Self::CertConf(inner) => inner.encoded_len(rules),
            Self::PollReq(inner) => inner.encoded_len(rules),
            Self::PollRep(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Ir(inner) => inner.encode(rules, out),
            Self::Ip(inner) => inner.encode(rules, out),
            Self::Cr(inner) => inner.encode(rules, out),
            Self::Cp(inner) => inner.encode(rules, out),
            Self::P10cr(inner) => inner.encode(rules, out),
            Self::Popdecc(inner) => inner.encode(rules, out),
            Self::Popdecr(inner) => inner.encode(rules, out),
            Self::Kur(inner) => inner.encode(rules, out),
            Self::Kup(inner) => inner.encode(rules, out),
            Self::Krr(inner) => inner.encode(rules, out),
            Self::Krp(inner) => inner.encode(rules, out),
            Self::Rr(inner) => inner.encode(rules, out),
            Self::Rp(inner) => inner.encode(rules, out),
            Self::Ccr(inner) => inner.encode(rules, out),
            Self::Ccp(inner) => inner.encode(rules, out),
            Self::Ckuann(inner) => inner.encode(rules, out),
            Self::Cann(inner) => inner.encode(rules, out),
            Self::Rann(inner) => inner.encode(rules, out),
            Self::Crlann(inner) => inner.encode(rules, out),
            Self::Pkiconf => Asn1Null.encode(rules, out),
            Self::Nested(inner) => inner.encode(rules, out),
            Self::Genm(inner) => inner.encode(rules, out),
            Self::Genp(inner) => inner.encode(rules, out),
            Self::Error(inner) => inner.encode(rules, out),
            Self::CertConf(inner) => inner.encode(rules, out),
            Self::PollReq(inner) => inner.encode(rules, out),
            Self::PollRep(inner) => inner.encode(rules, out),
        }
    }
}

impl EncodeTagged for PkiBody {}

impl Encode for PkiBody {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Ir(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::Ip(inner) => Explicit::new(&[0xa1], inner).encoded_len(rules),
            Self::Cr(inner) => Explicit::new(&[0xa2], inner).encoded_len(rules),
            Self::Cp(inner) => Explicit::new(&[0xa3], inner).encoded_len(rules),
            Self::P10cr(inner) => Explicit::new(&[0xa4], inner).encoded_len(rules),
            Self::Popdecc(inner) => Explicit::new(&[0xa5], inner).encoded_len(rules),
            Self::Popdecr(inner) => Explicit::new(&[0xa6], inner).encoded_len(rules),
            Self::Kur(inner) => Explicit::new(&[0xa7], inner).encoded_len(rules),
            Self::Kup(inner) => Explicit::new(&[0xa8], inner).encoded_len(rules),
            Self::Krr(inner) => Explicit::new(&[0xa9], inner).encoded_len(rules),
            Self::Krp(inner) => Explicit::new(&[0xaa], inner).encoded_len(rules),
            Self::Rr(inner) => Explicit::new(&[0xab], inner).encoded_len(rules),
            Self::Rp(inner) => Explicit::new(&[0xac], inner).encoded_len(rules),
            Self::Ccr(inner) => Explicit::new(&[0xad], inner).encoded_len(rules),
            Self::Ccp(inner) => Explicit::new(&[0xae], inner).encoded_len(rules),
            Self::Ckuann(inner) => Explicit::new(&[0xaf], inner).encoded_len(rules),
            Self::Cann(inner) => Explicit::new(&[0xb0], inner).encoded_len(rules),
            Self::Rann(inner) => Explicit::new(&[0xb1], inner).encoded_len(rules),
            Self::Crlann(inner) => Explicit::new(&[0xb2], inner).encoded_len(rules),
            Self::Pkiconf => Explicit::new(&[0xb3], &Asn1Null).encoded_len(rules),
            Self::Nested(inner) => Explicit::new(&[0xb4], inner).encoded_len(rules),
            Self::Genm(inner) => Explicit::new(&[0xb5], inner).encoded_len(rules),
            Self::Genp(inner) => Explicit::new(&[0xb6], inner).encoded_len(rules),
            Self::Error(inner) => Explicit::new(&[0xb7], inner).encoded_len(rules),
            Self::CertConf(inner) => Explicit::new(&[0xb8], inner).encoded_len(rules),
            Self::PollReq(inner) => Explicit::new(&[0xb9], inner).encoded_len(rules),
            Self::PollRep(inner) => Explicit::new(&[0xba], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Ir(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::Ip(inner) => Explicit::new(&[0xa1], inner).encode(rules, out),
            Self::Cr(inner) => Explicit::new(&[0xa2], inner).encode(rules, out),
            Self::Cp(inner) => Explicit::new(&[0xa3], inner).encode(rules, out),
            Self::P10cr(inner) => Explicit::new(&[0xa4], inner).encode(rules, out),
            Self::Popdecc(inner) => Explicit::new(&[0xa5], inner).encode(rules, out),
            Self::Popdecr(inner) => Explicit::new(&[0xa6], inner).encode(rules, out),
            Self::Kur(inner) => Explicit::new(&[0xa7], inner).encode(rules, out),
            Self::Kup(inner) => Explicit::new(&[0xa8], inner).encode(rules, out),
            Self::Krr(inner) => Explicit::new(&[0xa9], inner).encode(rules, out),
            Self::Krp(inner) => Explicit::new(&[0xaa], inner).encode(rules, out),
            Self::Rr(inner) => Explicit::new(&[0xab], inner).encode(rules, out),
            Self::Rp(inner) => Explicit::new(&[0xac], inner).encode(rules, out),
            Self::Ccr(inner) => Explicit::new(&[0xad], inner).encode(rules, out),
            Self::Ccp(inner) => Explicit::new(&[0xae], inner).encode(rules, out),
            Self::Ckuann(inner) => Explicit::new(&[0xaf], inner).encode(rules, out),
            Self::Cann(inner) => Explicit::new(&[0xb0], inner).encode(rules, out),
            Self::Rann(inner) => Explicit::new(&[0xb1], inner).encode(rules, out),
            Self::Crlann(inner) => Explicit::new(&[0xb2], inner).encode(rules, out),
            Self::Pkiconf => Explicit::new(&[0xb3], &Asn1Null).encode(rules, out),
            Self::Nested(inner) => Explicit::new(&[0xb4], inner).encode(rules, out),
            Self::Genm(inner) => Explicit::new(&[0xb5], inner).encode(rules, out),
            Self::Genp(inner) => Explicit::new(&[0xb6], inner).encode(rules, out),
            Self::Error(inner) => Explicit::new(&[0xb7], inner).encode(rules, out),
            Self::CertConf(inner) => Explicit::new(&[0xb8], inner).encode(rules, out),
            Self::PollReq(inner) => Explicit::new(&[0xb9], inner).encode(rules, out),
            Self::PollRep(inner) => Explicit::new(&[0xba], inner).encode(rules, out),
        }
    }
}
