use tc_algo::Algo;
use tc_asn1_cms::recipient::RecipientInfo;
use tc_x509::X509Operator;

use crate::CmsError;

// BC 的 RecipientInfoGenerator：把內容加密金鑰交給一個收件人
pub trait RecipientInfoGenerator: Send + Sync {
    fn generate(
        &self,
        algo: &dyn Algo,
        x509: &dyn X509Operator,
        content_key: &[u8],
    ) -> Result<RecipientInfo, CmsError>;
}
