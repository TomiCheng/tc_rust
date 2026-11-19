use tc_asn1::Asn1Oid;

use crate::CmsError;
use crate::digested::CmsDigestedData;

pub trait DigestedDataProvider: Send + Sync {
    // 內容封裝在裡面，摘要演算法不帶參數
    fn generate(&self, content: &[u8], digest: &Asn1Oid) -> Result<CmsDigestedData, CmsError>;

    // BC 的 Verify：摘要相符時給出內容，不符是 MessageDigestMismatch；沒封裝的內容是 MissingContent
    fn verify(&self, data: &CmsDigestedData) -> Result<Vec<u8>, CmsError>;
}
