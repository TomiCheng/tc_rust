use std::io::Read;

use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{CompressedData, ContentInfo, ContentType};
use tc_zlib::{InflateOptions, ZlibReader};

use crate::CmsError;
use crate::der::{convert, decode_all};

// BC 的 CmsCompressedData：壓縮過的內容
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsCompressedData {
    data: CompressedData,
}

impl CmsCompressedData {
    pub fn new(data: CompressedData) -> Self {
        Self { data }
    }

    // ContentInfo 包著的 CompressedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::COMPRESSED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info =
            ContentInfo::new(ContentType::COMPRESSED_DATA.oid()).with_content(convert(&self.data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn compressed_data(&self) -> &CompressedData {
        &self.data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.data.encap_content_info().content_type()
    }

    // BC 的 GetContent()：解壓後的內容。不認得的壓縮演算法是 UnknownAlgorithm
    pub fn content(&self) -> Result<Vec<u8>, CmsError> {
        self.inflate(None)
    }

    // BC 的 GetContent(limit)：解壓超過 limit bytes 是 ContentTooLarge，擋住壓縮炸彈
    pub fn content_with_limit(&self, limit: usize) -> Result<Vec<u8>, CmsError> {
        self.inflate(Some(limit))
    }

    fn inflate(&self, limit: Option<usize>) -> Result<Vec<u8>, CmsError> {
        if CompressedData::ZLIB_COMPRESS != *self.data.compression_algorithm().algorithm() {
            return Err(CmsError::UnknownAlgorithm);
        }
        let content = self
            .data
            .encap_content_info()
            .content()
            .ok_or(CmsError::MissingContent)?;
        let compressed: Asn1OctetString = decode_all(content.raw())?;
        let reader = ZlibReader::decompress(compressed.as_bytes(), InflateOptions::default());
        let mut output = Vec::new();
        match limit {
            None => {
                let mut reader = reader;
                reader.read_to_end(&mut output).map_err(CmsError::Io)?;
            }
            Some(limit) => {
                let mut reader = reader.take(limit as u64 + 1);
                reader.read_to_end(&mut output).map_err(CmsError::Io)?;
                if output.len() > limit {
                    return Err(CmsError::ContentTooLarge);
                }
            }
        }
        Ok(output)
    }
}
