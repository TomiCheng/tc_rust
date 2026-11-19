use std::sync::Arc;

use tc_algo::Params;
use tc_x509::cert::X509Certificate;

use crate::CmsError;
use crate::signed::{CmsSignedData, CmsSignedDataGenerator, SignerInformation};

pub trait SignedDataProvider: Send + Sync {
    // BC 的 CmsSignedDataGenerator.Generate；encapsulate 為 false 時內容不放進 SignedData
    fn generate(
        &self,
        generator: &CmsSignedDataGenerator,
        content: &[u8],
        encapsulate: bool,
    ) -> Result<CmsSignedData, CmsError>;

    // BC 的 SignerInformation.Verify(cert)：用憑證的公鑰驗證，有 signingTime 時憑證在那個時間要有效
    fn verify(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        certificate: &X509Certificate,
    ) -> Result<(), CmsError>;

    // BC 的 SignerInformation.Verify(publicKey)
    fn verify_with_key(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        public_key: Arc<dyn Params>,
    ) -> Result<(), CmsError>;
}
