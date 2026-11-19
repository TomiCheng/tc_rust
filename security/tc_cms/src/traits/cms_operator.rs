use crate::enveloped::EnvelopedDataProvider;
use crate::signed::SignedDataProvider;

pub trait CmsOperator: Send + Sync {
    // SignedData 的產生與驗證
    fn signed_data(&self) -> &dyn SignedDataProvider;

    // EnvelopedData 的加密與解密
    fn enveloped_data(&self) -> &dyn EnvelopedDataProvider;
}
