//! RFC 3274 `CompressedData`.
//!
//! ```text
//! CompressedData ::= SEQUENCE {
//!     version CMSVersion,       -- Always set to 0
//!     compressionAlgorithm CompressionAlgorithmIdentifier,
//!     encapContentInfo EncapsulatedContentInfo }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::content::ContentInfo;

/// Compressed content.
///
/// The version is always 0; a decoded version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CompressedData {
    version: Option<Asn1Integer>,
    compression_algorithm: AlgorithmIdentifier,
    encap_content_info: ContentInfo,
}

impl CompressedData {
    /// ZLIB compression (RFC 3274), `id-alg-zlibCompress`.
    pub const ZLIB_COMPRESS: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x08,
        ],
        "1.2.840.113549.1.9.16.3.8",
        "id-alg-zlibCompress",
    );

    /// The compression algorithm and the compressed content.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        compression_algorithm: AlgorithmIdentifier,
        encap_content_info: ContentInfo,
    ) -> Self {
        Self {
            version: None,
            compression_algorithm,
            encap_content_info,
        }
    }

    /// Returns the decoded version, or the one RFC 3274 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 0.
    fn derived_version(&self) -> Asn1Integer {
        0.into()
    }

    /// Returns the compression algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn compression_algorithm(&self) -> &AlgorithmIdentifier {
        &self.compression_algorithm
    }

    /// Returns the compressed content.
    /// Variable time: branches only on the encoding structure.
    pub fn encap_content_info(&self) -> &ContentInfo {
        &self.encap_content_info
    }
}

impl DecodeContent for CompressedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let compression_algorithm = fields.get()?;
        let encap_content_info = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            compression_algorithm,
            encap_content_info,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for CompressedData {
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

impl EncodeContent for CompressedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.compression_algorithm.encoded_len(rules)
            + self.encap_content_info.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.compression_algorithm.encode(rules, &mut out[at..])?;
        at += self.encap_content_info.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CompressedData {}

impl Tagged for CompressedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CompressedData {}

impl Encode for CompressedData {
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
    use alloc::string::ToString;

    use tc_asn1::{Asn1Any, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions, tag};
    use tc_asn1_x509::alg::AlgorithmIdentifier;

    use super::CompressedData;
    use crate::content::{ContentInfo, ContentType};

    #[test]
    fn zlib_compressed_data_is_version_zero_and_round_trips() {
        let zlib: Asn1Oid = CompressedData::ZLIB_COMPRESS.dotted().parse().unwrap();
        assert_eq!(CompressedData::ZLIB_COMPRESS.oid(), zlib);
        assert_eq!(zlib.to_string(), "1.2.840.113549.1.9.16.3.8");
        let value = CompressedData::new(
            AlgorithmIdentifier::new(zlib),
            ContentInfo::new(ContentType::DATA.oid()).with_content(Asn1Any::primitive(
                tag::OCTET_STRING,
                &[0x78, 0x9c, 3, 0, 0, 0, 0, 1],
            )),
        );
        assert_eq!(value.version(), 0.into());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            CompressedData::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }
}
