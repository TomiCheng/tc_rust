use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::auth_enveloped::{CmsAuthEnvelopedData, CmsAuthEnvelopedDataGenerator};
use crate::enveloped::RecipientInformation;

pub trait AuthEnvelopedDataProvider: Send + Sync {
    // 以亂數金鑰與 12 bytes 的 nonce 加密內容，ICV 16 bytes，同 BC Java；encryption 是 AES-GCM 或
    // AES-CCM 的 OID
    fn generate(
        &self,
        generator: &CmsAuthEnvelopedDataGenerator,
        content: &[u8],
        encryption: &Asn1Oid,
    ) -> Result<CmsAuthEnvelopedData, CmsError>;

    // key 依收件人種類，同 EnvelopedDataProvider::decrypt。內容、authenticated attributes 或 MAC
    // 被改過時是 AEAD 的 InvalidCiphertext
    fn decrypt(
        &self,
        data: &CmsAuthEnvelopedData,
        recipient: &RecipientInformation,
        key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError>;
}
