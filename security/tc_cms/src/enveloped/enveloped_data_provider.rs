use std::io::{Read, Write};

use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::enveloped::{
    CmsEnvelopedData, CmsEnvelopedDataGenerator, EnvelopedDataWriter, RecipientInformation,
};

pub trait EnvelopedDataProvider: Send + Sync {
    // BC 的 CmsEnvelopedDataGenerator.Generate(content, encryptionOid)：以亂數金鑰與 IV 加密內容，
    // 金鑰交給每個收件人。encryption 是 AES-128／192／256-CBC 或 DES-EDE3-CBC 的 OID
    fn generate(
        &self,
        generator: &CmsEnvelopedDataGenerator,
        content: &[u8],
        encryption: &Asn1Oid,
    ) -> Result<CmsEnvelopedData, CmsError>;

    // BC 的 CmsEnvelopedDataStreamGenerator.Open：收件人在這時就算好寫出，給出寫內容的串流，內容
    // 邊加密邊以 BER 不定長度分段寫到 output；寫完呼叫 finish
    fn open<'a>(
        &self,
        generator: &CmsEnvelopedDataGenerator,
        output: Box<dyn Write + 'a>,
        encryption: &Asn1Oid,
    ) -> Result<EnvelopedDataWriter<'a>, CmsError>;

    // BC 的 CmsEnvelopedDataParser 加 GetContentStream：select 挑出自己的收件人（第一個符合的），
    // key 同 decrypt；密文邊讀邊解密寫到 output，不整份放進記憶體。最後的 padding 錯誤要讀完才
    // 知道，在那之前的明文已經寫出，所以 output 要等這裡成功才能信任；沒有收件人符合是
    // WrongRecipientKey
    fn decrypt_stream(
        &self,
        input: &mut dyn Read,
        select: &dyn Fn(&RecipientInformation) -> bool,
        key: &dyn Params,
        output: &mut dyn Write,
    ) -> Result<(), CmsError>;

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
