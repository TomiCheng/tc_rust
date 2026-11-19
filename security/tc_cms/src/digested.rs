//! DigestedData（RFC 5652 §7），對應 BC 的 `CmsDigestedData`；BC 只讀取與驗證，產生照 RFC。

mod cms_digested_data;
mod default_digested_data_provider;
mod digested_data_provider;

pub use cms_digested_data::CmsDigestedData;
pub use digested_data_provider::DigestedDataProvider;
