//! SignedData，對應 BC 的 `CmsSignedData`、`CmsSignedDataGenerator` 與 `SignerInformation`。

mod algorithms;
mod cms_signed_data;
mod cms_signed_data_generator;
mod default_signed_data_provider;
mod signed_data_provider;
mod signer_info_generator;
mod signer_information;

pub use cms_signed_data::CmsSignedData;
pub use cms_signed_data_generator::CmsSignedDataGenerator;
pub use signed_data_provider::SignedDataProvider;
pub use signer_info_generator::SignerInfoGenerator;
pub use signer_information::SignerInformation;
