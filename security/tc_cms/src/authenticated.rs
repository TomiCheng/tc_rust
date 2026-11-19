//! AuthenticatedData（RFC 5652 §9），對應 BC 的 `CmsAuthenticatedData` 與
//! `CmsAuthenticatedDataGenerator`。收件人與 EnvelopedData 共用。

mod authenticated_data_provider;
mod cms_authenticated_data;
mod cms_authenticated_data_generator;
mod default_authenticated_data_provider;

pub use authenticated_data_provider::AuthenticatedDataProvider;
pub use cms_authenticated_data::CmsAuthenticatedData;
pub use cms_authenticated_data_generator::CmsAuthenticatedDataGenerator;
