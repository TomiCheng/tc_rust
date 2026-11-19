use std::io::{self, BufReader, Read, Write};

use tc_algo::Params;
use tc_algo::cipher::{Cipher, CipherDirection};
use tc_asn1::io::Asn1Reader;
use tc_asn1::{Asn1Any, Asn1Oid, Asn1SetOf};
use tc_asn1_cms::content::ContentType;
use tc_asn1_cms::recipient::RecipientInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::decode_all;
use crate::enveloped::RecipientInformation;
use crate::enveloped::default_enveloped_data_provider::content_params;
use crate::stream::{copy_octets, options, required};

// BC 的 CmsEnvelopedDataParser 加 GetContentStream：收件人在密文之前，先讀進來，交給 select 挑出
// 第一個符合的，以 key 取回內容金鑰，接著密文邊讀邊解密寫到 output。內容不整份放進記憶體；padding
// 錯誤在最後才知道，那時之前的明文已經寫出，CBC 也不驗證密文，所以 output 要等成功才能信任
pub(crate) fn decrypt(
    oper: &DefaultCmsOperator,
    input: &mut dyn Read,
    select: &dyn Fn(&RecipientInformation) -> bool,
    key: &dyn Params,
    output: &mut dyn Write,
) -> Result<(), CmsError> {
    let mut reader = Asn1Reader::new(BufReader::new(input), options());
    let mut info = required(reader.read_sequence())?;
    let content_type: Asn1Oid = required(info.read_value())?;
    if ContentType::ENVELOPED_DATA != content_type {
        return Err(CmsError::UnexpectedContentType);
    }
    let mut explicit = required(info.read_constructed(&[0xa0]))?;
    let mut enveloped = required(explicit.read_sequence())?;
    let _version: tc_asn1::Asn1Integer = required(enveloped.read_value())?;

    // originatorInfo [0] 可有可無，接著是 recipientInfos 的 SET
    let mut element: Asn1Any = required(enveloped.read_value())?;
    if element.raw().first() == Some(&0xa0) {
        element = required(enveloped.read_value())?;
    }
    let recipients: Asn1SetOf<RecipientInfo> = decode_all(element.raw())?;
    let recipient = recipients
        .members()
        .iter()
        .map(|info| RecipientInformation::new(info.clone()))
        .find(|recipient| select(recipient))
        .ok_or(CmsError::WrongRecipientKey)?;
    let content_key = oper.content_key(&recipient, key)?;

    let mut encrypted = required(enveloped.read_sequence())?;
    let _content_type: Asn1Oid = required(encrypted.read_value())?;
    let algorithm: AlgorithmIdentifier = required(encrypted.read_value())?;
    let mut cipher = oper.algo.cipher().get_by_oid(algorithm.algorithm())?;
    cipher.init(
        CipherDirection::Decrypt,
        content_params(&algorithm, &content_key)?.as_ref(),
    )?;

    let mut sink = DecryptingSink {
        cipher: &mut cipher,
        output,
    };
    let tag = encrypted
        .read_header()
        .map_err(CmsError::Io)?
        .ok_or(CmsError::MissingContent)?;
    encrypted.read_len().map_err(CmsError::Io)?;
    let mut body = encrypted.read_body().map_err(CmsError::Io)?;
    match tag.as_bytes() {
        // [0] IMPLICIT OCTET STRING，單一段
        [0x80] => {
            io::copy(&mut body, &mut sink).map_err(CmsError::Io)?;
        }
        // 分段的
        [0xa0] => copy_octets(&mut body, &mut sink)?,
        _ => return Err(tc_asn1::Asn1Error::UnexpectedTag.into()),
    }
    let last = cipher.finalize()?;
    output.write_all(&last).map_err(CmsError::Io)?;
    output.flush().map_err(CmsError::Io)
}

struct DecryptingSink<'a> {
    cipher: &'a mut Box<dyn Cipher>,
    output: &'a mut dyn Write,
}

impl Write for DecryptingSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let decrypted = self.cipher.update(buf).map_err(io::Error::other)?;
        self.output.write_all(&decrypted)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
