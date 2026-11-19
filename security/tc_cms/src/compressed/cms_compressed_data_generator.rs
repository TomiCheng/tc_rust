use std::io::Write;

use tc_asn1::{Asn1Oid, tag};
use tc_asn1_cms::content::{CompressedData, ContentInfo, ContentType};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zlib::{DeflateOptions, ZlibWriter};

use crate::CmsError;
use crate::compressed::CmsCompressedData;

// BC 的 CmsCompressedDataGenerator：以 zlib 壓縮內容，演算法是 id-alg-zlibCompress，沒有參數。
// 內容型別預設是 id-data。壓縮是變動時間，壓縮過的秘密會從長度洩漏內容，只用於公開值或在加密
// 之前、且攻擊者無法摻入內容時
pub struct CmsCompressedDataGenerator {
    content_type: Asn1Oid,
}

impl Default for CmsCompressedDataGenerator {
    fn default() -> Self {
        Self {
            content_type: ContentType::DATA.oid(),
        }
    }
}

impl CmsCompressedDataGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_content_type(&mut self, content_type: Asn1Oid) {
        self.content_type = content_type;
    }

    pub fn generate(&self, content: &[u8]) -> Result<CmsCompressedData, CmsError> {
        let mut writer = ZlibWriter::compress(Vec::new(), DeflateOptions::default());
        writer.write_all(content).map_err(CmsError::Io)?;
        let compressed = writer.finish().map_err(CmsError::Io)?;
        let encapsulated = ContentInfo::new(self.content_type.clone())
            .with_content(tc_asn1::Asn1Any::primitive(tag::OCTET_STRING, &compressed));
        Ok(CmsCompressedData::new(CompressedData::new(
            AlgorithmIdentifier::new(CompressedData::ZLIB_COMPRESS.oid()),
            encapsulated,
        )))
    }
}
