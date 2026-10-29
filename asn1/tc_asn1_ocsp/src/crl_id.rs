//! RFC 6960 §4.4.2 `CrlID`, the value of the CRL References extension:
//! the CRL on which a revoked or on-hold status was found.
//!
//! ```text
//! CrlID ::= SEQUENCE {
//!     crlUrl  [0] EXPLICIT IA5String OPTIONAL,
//!     crlNum  [1] EXPLICIT INTEGER OPTIONAL,
//!     crlTime [2] EXPLICIT GeneralizedTime OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ia5String, Asn1Integer, Asn1Ref, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};

/// The CRL by its location, number or creation time; any may be absent.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct CrlId {
    crl_url: Option<Asn1Ia5String>,
    crl_num: Option<Asn1Integer>,
    crl_time: Option<Asn1GeneralizedTime>,
}

impl CrlId {
    /// A reference with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            crl_url: None,
            crl_num: None,
            crl_time: None,
        }
    }

    /// Sets where the CRL is.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_url(mut self, crl_url: Asn1Ia5String) -> Self {
        self.crl_url = Some(crl_url);
        self
    }

    /// Sets the CRL number.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_num(mut self, crl_num: Asn1Integer) -> Self {
        self.crl_num = Some(crl_num);
        self
    }

    /// Sets when the CRL was created.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_time(mut self, crl_time: Asn1GeneralizedTime) -> Self {
        self.crl_time = Some(crl_time);
        self
    }

    /// Returns where the CRL is, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_url(&self) -> Option<&Asn1Ia5String> {
        self.crl_url.as_ref()
    }

    /// Returns the CRL number, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_num(&self) -> Option<&Asn1Integer> {
        self.crl_num.as_ref()
    }

    /// Returns when the CRL was created, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_time(&self) -> Option<&Asn1GeneralizedTime> {
        self.crl_time.as_ref()
    }
}

impl DecodeContent for CrlId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crl_url = fields.get_explicit_opt::<Asn1Ia5String>([0xa0])?;
        let crl_num = fields.get_explicit_opt::<Asn1Integer>([0xa1])?;
        let crl_time = fields.get_explicit_opt::<Asn1GeneralizedTime>([0xa2])?;
        fields.end()?;
        let value = Self {
            crl_url,
            crl_num,
            crl_time,
        };
        Ok(value)
    }
}

impl DecodeInner for CrlId {
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

impl EncodeContent for CrlId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crl_url
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .crl_num
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .crl_time
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.crl_url {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.crl_num {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.crl_time {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CrlId {}

impl Tagged for CrlId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlId {}

impl Encode for CrlId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
