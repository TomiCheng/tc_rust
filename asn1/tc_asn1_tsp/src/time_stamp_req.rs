//! RFC 3161 §2.4.1 `TimeStampReq`.
//!
//! ```text
//! TimeStampReq ::= SEQUENCE {
//!     version        INTEGER { v1(1) },
//!     messageImprint MessageImprint,
//!     reqPolicy      TSAPolicyId           OPTIONAL,
//!     nonce          INTEGER               OPTIONAL,
//!     certReq        BOOLEAN               DEFAULT FALSE,
//!     extensions     [0] IMPLICIT Extensions OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1Integer, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
    Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::MessageImprint;

/// A request to time-stamp a hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TimeStampReq {
    version: Option<Asn1Integer>,
    message_imprint: MessageImprint,
    req_policy: Option<Asn1Oid>,
    nonce: Option<Asn1Integer>,
    cert_req: bool,
    extensions: Option<Extensions>,
}

impl TimeStampReq {
    /// A version 1 request for this hash, with every option absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(message_imprint: MessageImprint) -> Self {
        Self {
            version: None,
            message_imprint,
            req_policy: None,
            nonce: None,
            cert_req: false,
            extensions: None,
        }
    }

    /// Sets the policy the TSA should issue under.
    /// Variable time: branches only on the encoding structure.
    pub fn with_req_policy(mut self, req_policy: Asn1Oid) -> Self {
        self.req_policy = Some(req_policy);
        self
    }

    /// Sets the nonce the token must echo.
    /// Variable time: branches only on the encoding structure.
    pub fn with_nonce(mut self, nonce: Asn1Integer) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Asks for the TSA certificate in the token.
    /// Variable time: branches only on the encoding structure.
    pub fn with_cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Sets the extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Returns the decoded version, or the one RFC 3161 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 1.
    fn derived_version(&self) -> Asn1Integer {
        1.into()
    }

    /// Returns the hash to time-stamp.
    /// Variable time: branches only on the encoding structure.
    pub fn message_imprint(&self) -> &MessageImprint {
        &self.message_imprint
    }

    /// Returns the policy asked for, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn req_policy(&self) -> Option<&Asn1Oid> {
        self.req_policy.as_ref()
    }

    /// Returns the nonce, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn nonce(&self) -> Option<&Asn1Integer> {
        self.nonce.as_ref()
    }

    /// Returns whether the TSA certificate is asked for.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req(&self) -> bool {
        self.cert_req
    }

    /// Returns the extensions, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeContent for TimeStampReq {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let message_imprint = fields.get()?;
        let req_policy = fields.get_opt()?;
        let nonce = fields.get_opt()?;
        let cert_req = fields.get_default(Asn1Boolean::from(false))?.is_true();
        let extensions = fields.get_implicit_opt([0xa0])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            message_imprint,
            req_policy,
            nonce,
            cert_req,
            extensions,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for TimeStampReq {
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

impl EncodeContent for TimeStampReq {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.message_imprint.encoded_len(rules)
            + self.req_policy.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.nonce.as_ref().map_or(0, |v| v.encoded_len(rules))
            + (if self.cert_req {
                Asn1Boolean::from(true).encoded_len(rules)
            } else {
                0
            })
            + self
                .extensions
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.message_imprint.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.req_policy {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.nonce {
            at += v.encode(rules, &mut out[at..])?;
        }
        if self.cert_req {
            at += Asn1Boolean::from(true).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.extensions {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TimeStampReq {}

impl Tagged for TimeStampReq {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TimeStampReq {}

impl Encode for TimeStampReq {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
