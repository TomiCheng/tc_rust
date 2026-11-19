use crate::auth_enveloped::AuthEnvelopedDataProvider;
use crate::authenticated::AuthenticatedDataProvider;
use crate::digested::DigestedDataProvider;
use crate::enveloped::EnvelopedDataProvider;
use crate::signed::SignedDataProvider;

pub trait CmsOperator: Send + Sync {
    // SignedData 的產生與驗證
    fn signed_data(&self) -> &dyn SignedDataProvider;

    // EnvelopedData 的加密與解密
    fn enveloped_data(&self) -> &dyn EnvelopedDataProvider;

    // AuthEnvelopedData 的加密與解密
    fn auth_enveloped_data(&self) -> &dyn AuthEnvelopedDataProvider;

    // AuthenticatedData 的產生與驗證
    fn authenticated_data(&self) -> &dyn AuthenticatedDataProvider;

    // DigestedData 的產生與驗證
    fn digested_data(&self) -> &dyn DigestedDataProvider;
}
