//! RFC 3161 §2.4.2 `TSTInfo`, the content a time-stamp token signs.
//!
//! ```text
//! TSTInfo ::= SEQUENCE {
//!     version        INTEGER { v1(1) },
//!     policy         TSAPolicyId,
//!     messageImprint MessageImprint,
//!     serialNumber   INTEGER,
//!     genTime        GeneralizedTime,
//!     accuracy       Accuracy              OPTIONAL,
//!     ordering       BOOLEAN               DEFAULT FALSE,
//!     nonce          INTEGER               OPTIONAL,
//!     tsa            [0] GeneralName       OPTIONAL,
//!     extensions     [1] IMPLICIT Extensions OPTIONAL }
//! ```
//!
//! `tsa` is a CHOICE, so its tag is explicit despite the module's implicit tags.

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1Oid, Asn1Ref, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Implicit, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;
use tc_asn1_x509::name::GeneralName;

use crate::{Accuracy, MessageImprint};

/// What was time-stamped, when, under which policy, and by whom.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TstInfo {
    version: Option<Asn1Integer>,
    policy: Asn1Oid,
    message_imprint: MessageImprint,
    serial_number: Asn1Integer,
    gen_time: Asn1GeneralizedTime,
    accuracy: Option<Accuracy>,
    ordering: bool,
    nonce: Option<Asn1Integer>,
    tsa: Option<GeneralName>,
    extensions: Option<Extensions>,
}

impl TstInfo {
    /// A version 1 token content, with every option absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        policy: Asn1Oid,
        message_imprint: MessageImprint,
        serial_number: Asn1Integer,
        gen_time: Asn1GeneralizedTime,
    ) -> Self {
        Self {
            version: None,
            policy,
            message_imprint,
            serial_number,
            gen_time,
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        }
    }

    /// Sets the accuracy of the time.
    /// Variable time: branches only on the encoding structure.
    pub fn with_accuracy(mut self, accuracy: Accuracy) -> Self {
        self.accuracy = Some(accuracy);
        self
    }

    /// Declares that tokens from this TSA can be ordered by their time alone.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ordering(mut self, ordering: bool) -> Self {
        self.ordering = ordering;
        self
    }

    /// Sets the nonce from the request.
    /// Variable time: branches only on the encoding structure.
    pub fn with_nonce(mut self, nonce: Asn1Integer) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the TSA's name.
    /// Variable time: branches only on the encoding structure.
    pub fn with_tsa(mut self, tsa: GeneralName) -> Self {
        self.tsa = Some(tsa);
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

    /// Returns the policy the token was issued under.
    /// Variable time: branches only on the encoding structure.
    pub fn policy(&self) -> &Asn1Oid {
        &self.policy
    }

    /// Returns the hash time-stamped.
    /// Variable time: branches only on the encoding structure.
    pub fn message_imprint(&self) -> &MessageImprint {
        &self.message_imprint
    }

    /// Returns the serial number, unique per TSA.
    /// Variable time: branches only on the encoding structure.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }

    /// Returns when the token was created.
    /// Variable time: branches only on the encoding structure.
    pub fn gen_time(&self) -> &Asn1GeneralizedTime {
        &self.gen_time
    }

    /// Returns the accuracy of the time, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn accuracy(&self) -> Option<&Accuracy> {
        self.accuracy.as_ref()
    }

    /// Returns whether tokens from this TSA can be ordered by their time alone.
    /// Variable time: branches only on the encoding structure.
    pub fn ordering(&self) -> bool {
        self.ordering
    }

    /// Returns the nonce from the request, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn nonce(&self) -> Option<&Asn1Integer> {
        self.nonce.as_ref()
    }

    /// Returns the TSA's name, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn tsa(&self) -> Option<&GeneralName> {
        self.tsa.as_ref()
    }

    /// Returns the extensions, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeContent for TstInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let policy = fields.get()?;
        let message_imprint = fields.get()?;
        let serial_number = fields.get()?;
        let gen_time = fields.get()?;
        let accuracy = fields.get_opt()?;
        let ordering = fields.get_default(Asn1Boolean::from(false))?.is_true();
        let nonce = fields.get_opt()?;
        let tsa = fields.get_explicit_opt::<GeneralName>([0xa0])?;
        let extensions = fields.get_implicit_opt([0xa1])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            policy,
            message_imprint,
            serial_number,
            gen_time,
            accuracy,
            ordering,
            nonce,
            tsa,
            extensions,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for TstInfo {
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

impl EncodeContent for TstInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.policy.encoded_len(rules)
            + self.message_imprint.encoded_len(rules)
            + self.serial_number.encoded_len(rules)
            + self.gen_time.encoded_len(rules)
            + self.accuracy.as_ref().map_or(0, |v| v.encoded_len(rules))
            + (if self.ordering {
                Asn1Boolean::from(true).encoded_len(rules)
            } else {
                0
            })
            + self.nonce.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .tsa
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .extensions
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.policy.encode(rules, &mut out[at..])?;
        at += self.message_imprint.encode(rules, &mut out[at..])?;
        at += self.serial_number.encode(rules, &mut out[at..])?;
        at += self.gen_time.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.accuracy {
            at += v.encode(rules, &mut out[at..])?;
        }
        if self.ordering {
            at += Asn1Boolean::from(true).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.nonce {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.tsa {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.extensions {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TstInfo {}

impl Tagged for TstInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TstInfo {}

impl Encode for TstInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
