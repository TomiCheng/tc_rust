//! EnvelopedData，對應 BC 的 `CmsEnvelopedData`、`CmsEnvelopedDataGenerator` 與
//! `RecipientInformation`。

mod cms_enveloped_data;
mod cms_enveloped_data_generator;
mod default_enveloped_data_provider;
mod enveloped_data_provider;
mod key_trans_recipient_info_generator;
mod recipient_info_generator;
mod recipient_information;

pub use cms_enveloped_data::CmsEnvelopedData;
pub use cms_enveloped_data_generator::CmsEnvelopedDataGenerator;
pub use enveloped_data_provider::EnvelopedDataProvider;
pub use key_trans_recipient_info_generator::KeyTransRecipientInfoGenerator;
pub use recipient_info_generator::RecipientInfoGenerator;
pub use recipient_information::RecipientInformation;
