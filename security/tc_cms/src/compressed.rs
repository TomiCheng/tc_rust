//! CompressedData（RFC 3274），對應 BC 的 `CmsCompressedData` 與
//! `CmsCompressedDataGenerator`，以 tc_zlib 壓縮。

mod cms_compressed_data;
mod cms_compressed_data_generator;

pub use cms_compressed_data::CmsCompressedData;
pub use cms_compressed_data_generator::CmsCompressedDataGenerator;
