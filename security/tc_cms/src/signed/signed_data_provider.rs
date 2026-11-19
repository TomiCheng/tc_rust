use std::io::{Read, Write};
use std::sync::Arc;

use tc_algo::Params;
use tc_x509::cert::X509Certificate;

use crate::CmsError;
use crate::signed::{CmsSignedData, CmsSignedDataGenerator, SignedDataWriter, SignerInformation};

pub trait SignedDataProvider: Send + Sync {
    // BC 的 CmsSignedDataGenerator.Generate；encapsulate 為 false 時內容不放進 SignedData
    fn generate(
        &self,
        generator: &CmsSignedDataGenerator,
        content: &[u8],
        encapsulate: bool,
    ) -> Result<CmsSignedData, CmsError>;

    // BC 的 CmsSignedDataStreamGenerator.Open：給出寫內容的串流，內容邊寫邊算摘要，封裝時以 BER
    // 不定長度分段寫到 output；寫完呼叫 finish 寫出簽署者
    fn open<'a>(
        &'a self,
        generator: &'a CmsSignedDataGenerator,
        output: Box<dyn Write + 'a>,
        encapsulate: bool,
    ) -> Result<SignedDataWriter<'a>, CmsError>;

    // BC 的 CmsSignedDataParser：封裝的內容邊讀邊寫到 content 並算摘要，不整份放進記憶體。給出的
    // CmsSignedData 沒有內容，verify 以算好的摘要驗證；不帶 signed attributes 的簽署者要整份內容，
    // 驗不了，是 MissingContent
    fn parse(
        &self,
        input: &mut dyn Read,
        content: &mut dyn Write,
    ) -> Result<CmsSignedData, CmsError>;

    // 沒封裝的 SignedData，內容另外從 content 邊讀邊算摘要
    fn parse_detached(
        &self,
        input: &mut dyn Read,
        content: &mut dyn Read,
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
