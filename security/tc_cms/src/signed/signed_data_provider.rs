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

    // BC 的 GenerateCounterSigners 加 AddCounterSigners 與 ReplaceSigners：generator 的每個簽署者
    // 副署 signer 的簽章值，寫進它的 countersignature 屬性，給出換掉這個簽署者的 SignedData。
    // 副署不帶 contentType；signer 不在 signed 的最上層是 NoSigner，所以不能副署副署
    fn countersign(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        generator: &CmsSignedDataGenerator,
    ) -> Result<CmsSignedData, CmsError>;

    // BC 的 SignerInformation.Verify(publicKey)
    fn verify_with_key(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        public_key: Arc<dyn Params>,
    ) -> Result<(), CmsError>;
}
