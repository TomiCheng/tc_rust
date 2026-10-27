//! RFC 5544 `TimeStampedData`, content bound to one or more time stamps.
//!
//! ```text
//! TimeStampedData ::= SEQUENCE {
//!     version              INTEGER { v1(1) },
//!     dataUri              IA5String OPTIONAL,
//!     metaData             MetaData OPTIONAL,
//!     content              OCTET STRING OPTIONAL,
//!     temporalEvidence     Evidence }
//! ```

use crate::tsd::{Evidence, MetaData};
use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged, tag,
};

/// Content, or a URI to it, and the evidence of when it existed.
///
/// The version is always 1; a decoded version that differs is kept.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::content::{ContentInfo, ContentType};
/// use tc_asn1_cms::tsd::{TimeStampAndCrl, TimeStampTokenEvidence, TimeStampedData};
///
/// // The time-stamp token is an RFC 3161 SignedData, elided here.
/// let token = ContentInfo::new(ContentType::SIGNED_DATA.oid());
/// let evidence = TimeStampTokenEvidence::new(vec![TimeStampAndCrl::new(token)])?;
/// let stamped = TimeStampedData::new(evidence.into())
///     .with_content(Asn1OctetString::new(b"contract text"));
/// assert_eq!(stamped.version(), 1.into());
/// let der = stamped.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(TimeStampedData::decode_der(&der, &DecodingOptions::default())?.1, stamped);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TimeStampedData {
    version: Option<Asn1Integer>,
    data_uri: Option<Asn1Ia5String>,
    meta_data: Option<MetaData>,
    content: Option<Asn1OctetString>,
    temporal_evidence: Evidence,
}

impl TimeStampedData {
    /// The evidence alone, with neither the content nor a URI to it.
    /// Variable time: branches only on the encoding structure.
    pub fn new(temporal_evidence: Evidence) -> Self {
        Self {
            version: None,
            data_uri: None,
            meta_data: None,
            content: None,
            temporal_evidence,
        }
    }

    /// Adds the URI where the content can be found.
    /// Variable time: branches only on the encoding structure.
    pub fn with_data_uri(mut self, data_uri: Asn1Ia5String) -> Self {
        self.data_uri = Some(data_uri);
        self
    }

    /// Adds the metadata.
    /// Variable time: branches only on the encoding structure.
    pub fn with_meta_data(mut self, meta_data: MetaData) -> Self {
        self.meta_data = Some(meta_data);
        self
    }

    /// Adds the content itself.
    /// Variable time: branches only on the encoding structure.
    pub fn with_content(mut self, content: Asn1OctetString) -> Self {
        self.content = Some(content);
        self
    }

    /// Returns the decoded version, or the one RFC 5544 calls for.
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

    /// Returns the URI of the content, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn data_uri(&self) -> Option<&Asn1Ia5String> {
        self.data_uri.as_ref()
    }

    /// Returns the metadata, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn meta_data(&self) -> Option<&MetaData> {
        self.meta_data.as_ref()
    }

    /// Returns the content, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn content(&self) -> Option<&Asn1OctetString> {
        self.content.as_ref()
    }

    /// Returns the evidence of when the content existed.
    /// Variable time: branches only on the encoding structure.
    pub fn temporal_evidence(&self) -> &Evidence {
        &self.temporal_evidence
    }
}

impl DecodeContent for TimeStampedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let data_uri = fields.get_opt()?;
        let meta_data = fields.get_opt()?;
        let content = fields.get_opt()?;
        let temporal_evidence = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            data_uri,
            meta_data,
            content,
            temporal_evidence,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for TimeStampedData {
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

impl EncodeContent for TimeStampedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.data_uri.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.meta_data.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.content.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.temporal_evidence.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        if let Some(v) = &self.data_uri {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.meta_data {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.content {
            at += v.encode(rules, &mut out[at..])?;
        }
        at += self.temporal_evidence.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for TimeStampedData {}

impl Tagged for TimeStampedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TimeStampedData {}

impl Encode for TimeStampedData {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{
        Asn1Any, Asn1Boolean, Asn1Error, Asn1Ia5String, Asn1OctetString, Asn1Utf8String, Decode,
        DecodingOptions, Encode, EncodingOptions,
    };

    use super::TimeStampedData;
    use crate::content::{ContentInfo, ContentType};
    use crate::fixtures::{attribute, crl};
    use crate::tsd::{Evidence, MetaData, TimeStampAndCrl, TimeStampTokenEvidence};

    fn evidence() -> Evidence {
        let token = ContentInfo::new(ContentType::SIGNED_DATA.oid());
        TimeStampTokenEvidence::new(vec![
            TimeStampAndCrl::new(token.clone()),
            TimeStampAndCrl::new(token).with_crl(crl()),
        ])
        .unwrap()
        .into()
    }

    #[test]
    fn every_optional_field_and_both_kinds_of_evidence_round_trip() {
        let meta = MetaData::new(Asn1Boolean::from(true))
            .with_file_name(Asn1Utf8String::new("contract.txt"))
            .with_media_type(Asn1Ia5String::new("text/plain").unwrap())
            .with_other_meta_data(vec![attribute()]);
        let full = TimeStampedData::new(evidence())
            .with_data_uri(Asn1Ia5String::new("https://example.com/contract.txt").unwrap())
            .with_meta_data(meta)
            .with_content(Asn1OctetString::new(b"contract text"));
        let ers = TimeStampedData::new(Evidence::Ers(
            Asn1Any::decode(&[0xa1, 0x03, 0x02, 0x01, 0x01], &DecodingOptions::default())
                .unwrap()
                .1,
        ));
        for value in [full, ers] {
            assert_eq!(value.version(), 1.into());
            for rules in [EncodingOptions::BER, EncodingOptions::DER] {
                let wire = value.encode_to_vec(&rules).unwrap();
                assert_eq!(
                    TimeStampedData::decode(&wire, &DecodingOptions::default())
                        .unwrap()
                        .1,
                    value
                );
            }
        }
    }

    #[test]
    fn empty_time_stamp_evidence_and_unknown_evidence_tags_are_rejected() {
        assert_eq!(
            TimeStampTokenEvidence::new(vec![]),
            Err(Asn1Error::MalformedValue)
        );
        for (evidence, error) in [
            (&[0xa0, 0x00][..], Asn1Error::MalformedValue),
            (&[0xa3, 0x00][..], Asn1Error::UnexpectedTag),
        ] {
            let wire = [
                &[0x30, 3 + evidence.len() as u8, 0x02, 0x01, 0x01][..],
                evidence,
            ]
            .concat();
            assert_eq!(
                TimeStampedData::decode_der(&wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
