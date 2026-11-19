use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::enveloped::{CmsEnvelopedData, CmsEnvelopedDataGenerator, RecipientInformation};

pub trait EnvelopedDataProvider: Send + Sync {
    // BC 的 CmsEnvelopedDataGenerator.Generate(content, encryptionOid)：以亂數金鑰與 IV 加密內容，
    // 金鑰交給每個收件人。encryption 是 AES-128／192／256-CBC 或 DES-EDE3-CBC 的 OID
    fn generate(
        &self,
        generator: &CmsEnvelopedDataGenerator,
        content: &[u8],
        encryption: &Asn1Oid,
    ) -> Result<CmsEnvelopedData, CmsError>;

    // BC 的 RecipientInformation.GetContent(key)：KeyTrans 給 RSA 私鑰，KeyAgree 給 KeyAgreeKey，KEK
    // 給 KeyOwned，Password 給 PasswordKey；其他型別是 WrongRecipientKey。金鑰不對時通常是 padding 或 unwrap 錯誤，但
    // PKCS#1 v1.5 偶爾會解出錯的金鑰，於是內容的 padding 錯
    fn decrypt(
        &self,
        enveloped: &CmsEnvelopedData,
        recipient: &RecipientInformation,
        key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError>;
}
