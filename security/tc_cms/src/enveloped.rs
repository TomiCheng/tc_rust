//! EnvelopedData，對應 BC 的 `CmsEnvelopedData`、`CmsEnvelopedDataGenerator` 與
//! `RecipientInformation`。

mod cms_enveloped_data;
mod cms_enveloped_data_generator;
mod default_enveloped_data_provider;
mod enveloped_data_provider;
mod kek_recipient_info_generator;
mod key_agree_key;
mod key_agree_recipient_info_generator;
mod key_trans_recipient_info_generator;
mod password_key;
mod password_recipient_info_generator;
mod rc2_cbc;
mod recipient_info_generator;
mod recipient_information;

pub use cms_enveloped_data::CmsEnvelopedData;
pub use cms_enveloped_data_generator::CmsEnvelopedDataGenerator;
pub(crate) use default_enveloped_data_provider::random;
pub use enveloped_data_provider::EnvelopedDataProvider;
pub use kek_recipient_info_generator::KekRecipientInfoGenerator;
pub use key_agree_key::KeyAgreeKey;
pub use key_agree_recipient_info_generator::KeyAgreeRecipientInfoGenerator;
pub use key_trans_recipient_info_generator::KeyTransRecipientInfoGenerator;
pub use password_key::PasswordKey;
pub use password_recipient_info_generator::PasswordRecipientInfoGenerator;
pub use recipient_info_generator::RecipientInfoGenerator;
pub use recipient_information::RecipientInformation;
