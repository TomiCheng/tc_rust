use std::io::{self, Write};

use tc_algo::cipher::{Cipher, CipherDirection};
use tc_algo::params::cipher::KeyWithIvOwned;
use tc_asn1::{
    Asn1Integer, Asn1Object, Asn1OctetString, Asn1Oid, Asn1SetOf, Encode, EncodingOptions,
};
use tc_asn1_cms::content::{ContentType, EncryptedContentInfo, EnvelopedData};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::content_key_length;
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::length;
use crate::enveloped::{CmsEnvelopedDataGenerator, random};

// 每段 OCTET STRING 的最大長度
const SEGMENT: usize = 4096;

// BC 的 CmsEnvelopedDataStreamGenerator.Open 給的串流：收件人在 open 時就寫出，寫進來的內容邊
// 加密邊以 BER 不定長度分段寫出，finish 時寫出最後的區塊並收尾。沒有呼叫 finish 就丟掉，輸出是
// 不完整的
pub struct EnvelopedDataWriter<'a> {
    output: Box<dyn Write + 'a>,
    cipher: Box<dyn Cipher>,
    pending: Vec<u8>,
}

impl<'a> EnvelopedDataWriter<'a> {
    pub(crate) fn open(
        oper: &DefaultCmsOperator,
        generator: &CmsEnvelopedDataGenerator,
        mut output: Box<dyn Write + 'a>,
        encryption: &Asn1Oid,
    ) -> Result<Self, CmsError> {
        let key = Zeroizing::new(random(content_key_length(encryption)?));
        let mut cipher = oper.algo.cipher().get_by_oid(encryption)?;
        let iv = random(cipher.block_size());
        cipher.init(
            CipherDirection::Encrypt,
            &KeyWithIvOwned::new(key.to_vec(), iv.clone()),
        )?;

        let mut recipients = Vec::new();
        for recipient in &generator.recipients {
            recipients.push(recipient.generate(oper.algo.as_ref(), oper.x509.as_ref(), &key)?);
        }
        let algorithm = AlgorithmIdentifier::with_parameters(
            encryption.clone(),
            Asn1Object::OctetString(Asn1OctetString::new(&iv)),
        );
        // 版本依收件人而定，以一份沒有內容的 EnvelopedData 算出
        let version: Asn1Integer = EnvelopedData::new(
            recipients.clone(),
            EncryptedContentInfo::new(generator.content_type.clone(), algorithm.clone()),
        )
        .version();

        let mut head = Vec::new();
        head.extend([0x30, 0x80]);
        head.extend(
            ContentType::ENVELOPED_DATA
                .oid()
                .encode_to_vec(&EncodingOptions::DER)?,
        );
        head.extend([0xa0, 0x80, 0x30, 0x80]);
        head.extend(version.encode_to_vec(&EncodingOptions::DER)?);
        head.extend(Asn1SetOf::new(recipients).encode_to_vec(&EncodingOptions::DER)?);
        head.extend([0x30, 0x80]);
        head.extend(
            generator
                .content_type
                .encode_to_vec(&EncodingOptions::DER)?,
        );
        head.extend(algorithm.encode_to_vec(&EncodingOptions::DER)?);
        // encryptedContent 是 [0] IMPLICIT OCTET STRING，分段時是 constructed 的 [0]
        head.extend([0xa0, 0x80]);
        output.write_all(&head).map_err(CmsError::Io)?;

        Ok(Self {
            output,
            cipher,
            pending: Vec::new(),
        })
    }

    // 寫出最後的區塊（含 padding）並收尾
    pub fn finish(mut self) -> Result<(), CmsError> {
        let last = self.cipher.finalize()?;
        self.pending.extend(last);
        self.flush_segment()?;
        // [0]、EncryptedContentInfo、EnvelopedData、[0]、ContentInfo
        self.output.write_all(&[0; 10]).map_err(CmsError::Io)?;
        self.output.flush().map_err(CmsError::Io)
    }

    fn flush_segment(&mut self) -> Result<(), CmsError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut header = vec![0x04];
        length(&mut header, self.pending.len());
        self.output.write_all(&header).map_err(CmsError::Io)?;
        self.output.write_all(&self.pending).map_err(CmsError::Io)?;
        self.pending.clear();
        Ok(())
    }
}

impl Write for EnvelopedDataWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let encrypted = self.cipher.update(buf).map_err(io::Error::other)?;
        self.pending.extend(encrypted);
        if self.pending.len() >= SEGMENT {
            self.flush_segment().map_err(io::Error::other)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
