//! AuthEnvelopedData（RFC 5083），照 BC Java 的 `CMSAuthEnvelopedData`：BC C# 讀得到但沒有實作
//! 解密。收件人與 EnvelopedData 共用。

mod auth_enveloped_data_provider;
mod cms_auth_enveloped_data;
mod cms_auth_enveloped_data_generator;
mod default_auth_enveloped_data_provider;

pub use auth_enveloped_data_provider::AuthEnvelopedDataProvider;
pub use cms_auth_enveloped_data::CmsAuthEnvelopedData;
pub use cms_auth_enveloped_data_generator::CmsAuthEnvelopedDataGenerator;
