//! EncryptedData（RFC 5652 §8）：以雙方事先共享的對稱金鑰加密的內容，沒有收件人。BC C# 只有
//! ASN.1 型別，這裡照 RFC 與 BC Java 的 CMSEncryptedData。

mod cms_encrypted_data;
mod default_encrypted_data_provider;
mod encrypted_data_provider;

pub use cms_encrypted_data::CmsEncryptedData;
pub use encrypted_data_provider::EncryptedDataProvider;
