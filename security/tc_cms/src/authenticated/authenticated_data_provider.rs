use tc_algo::Params;
use tc_asn1::Asn1Oid;

use crate::CmsError;
use crate::authenticated::{CmsAuthenticatedData, CmsAuthenticatedDataGenerator};
use crate::enveloped::RecipientInformation;

pub trait AuthenticatedDataProvider: Send + Sync {
    // BC 的 CmsAuthenticatedDataGenerator.Generate(content, macOid)：亂數的 MAC 金鑰，長度是 HMAC
    // 摘要的長度，交給每個收件人。mac 是 HMAC-SHA1 到 HMAC-SHA512 的 OID；內容封裝在裡面
    fn generate(
        &self,
        generator: &CmsAuthenticatedDataGenerator,
        content: &[u8],
        mac: &Asn1Oid,
    ) -> Result<CmsAuthenticatedData, CmsError>;

    // 取回 MAC 金鑰並驗證，通過時給出內容；key 依收件人種類，同 EnvelopedDataProvider::decrypt。
    // BC C# 只算出 MAC 由呼叫端比對，這裡直接比對，不符是 MacMismatch
    fn verify(
        &self,
        data: &CmsAuthenticatedData,
        recipient: &RecipientInformation,
        key: &dyn Params,
    ) -> Result<Vec<u8>, CmsError>;
}
