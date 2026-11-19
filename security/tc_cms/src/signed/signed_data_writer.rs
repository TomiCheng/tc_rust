use std::io::{self, Write};

use tc_algo::Algo;
use tc_algo::digest::Digest;
use tc_asn1::{Asn1Integer, Asn1Oid, Asn1SetOf, Encode, EncodingOptions};
use tc_asn1_cms::content::{CertificateChoices, ContentType};
use tc_asn1_cms::signed::SignerIdentifier;
use tc_x509::operator::{BlockResult, StreamCalculator};

use crate::CmsError;
use crate::der::length;
use crate::signed::CmsSignedDataGenerator;
use crate::signed::default_signed_data_provider::{finish_signer_info, sign_digest};

// 每段 OCTET STRING 的最大長度
const SEGMENT: usize = 4096;

type Calculator = Box<dyn StreamCalculator<Box<dyn BlockResult>>>;

// BC 的 CmsSignedDataStreamGenerator.Open 給的串流：寫進來的內容邊算摘要，封裝時以 BER 不定長度
// 分段寫出，finish 時寫出簽署者並收尾。沒有呼叫 finish 就丟掉，輸出是不完整的
pub struct SignedDataWriter<'a> {
    output: Box<dyn Write + 'a>,
    generator: &'a CmsSignedDataGenerator,
    encapsulate: bool,
    digests: Vec<(Asn1Oid, Box<dyn Digest>)>,
    // 不帶 signed attributes 的簽署者直接簽內容，依簽署者的順序
    direct: Vec<Option<Calculator>>,
    pending: Vec<u8>,
}

impl<'a> SignedDataWriter<'a> {
    pub(crate) fn open(
        algo: &dyn Algo,
        generator: &'a CmsSignedDataGenerator,
        mut output: Box<dyn Write + 'a>,
        encapsulate: bool,
    ) -> Result<Self, CmsError> {
        let mut digests: Vec<(Asn1Oid, Box<dyn Digest>)> = Vec::new();
        let mut direct = Vec::new();
        for signer in &generator.signers {
            let oid = signer.digest_algorithm.algorithm();
            if !digests.iter().any(|(known, _)| known == oid) {
                digests.push((oid.clone(), algo.digest().get_by_oid(oid)?));
            }
            direct.push(if signer.signed_attributes {
                None
            } else {
                Some(signer.factory.create_calculator()?)
            });
        }

        // ContentInfo、[0]、SignedData 都是不定長度，簽署者在內容之後才知道
        let mut head = Vec::new();
        indefinite(&mut head, 0x30);
        head.extend(
            ContentType::SIGNED_DATA
                .oid()
                .encode_to_vec(&EncodingOptions::DER)?,
        );
        indefinite(&mut head, 0xa0);
        indefinite(&mut head, 0x30);
        head.extend(Asn1Integer::from(version(generator)).encode_to_vec(&EncodingOptions::DER)?);
        let algorithms: Vec<_> = generator
            .signers
            .iter()
            .map(|signer| signer.digest_algorithm.clone())
            .fold(Vec::new(), |mut unique, algorithm| {
                if !unique.contains(&algorithm) {
                    unique.push(algorithm);
                }
                unique
            });
        head.extend(Asn1SetOf::new(algorithms).encode_to_vec(&EncodingOptions::DER)?);
        indefinite(&mut head, 0x30);
        head.extend(
            generator
                .content_type
                .encode_to_vec(&EncodingOptions::DER)?,
        );
        if encapsulate {
            indefinite(&mut head, 0xa0);
            indefinite(&mut head, 0x24);
        }
        output.write_all(&head).map_err(CmsError::Io)?;

        Ok(Self {
            output,
            generator,
            encapsulate,
            digests,
            direct,
            pending: Vec::new(),
        })
    }

    // 寫出剩下的內容、憑證與簽署者，並收尾
    pub fn finish(mut self) -> Result<(), CmsError> {
        self.flush_segment()?;
        let mut tail = Vec::new();
        if self.encapsulate {
            tail.extend([0, 0, 0, 0]);
        }
        tail.extend([0, 0]);

        if !self.generator.certificates.is_empty() {
            let certificates: Vec<_> = self
                .generator
                .certificates
                .iter()
                .map(|certificate| {
                    CertificateChoices::Certificate(certificate.certificate().clone())
                })
                .collect();
            let mut der = Asn1SetOf::new(certificates).encode_to_vec(&EncodingOptions::DER)?;
            // [0] IMPLICIT SET OF：只換標籤
            der[0] = 0xa0;
            tail.extend(der);
        }

        let mut computed = Vec::new();
        for (oid, digest) in &mut self.digests {
            computed.push((oid.clone(), digest.finalize()?));
        }
        let mut signer_infos = Vec::new();
        for (signer, direct) in self.generator.signers.iter().zip(self.direct.iter_mut()) {
            let info = match direct.take() {
                Some(calculator) => {
                    finish_signer_info(signer, None, calculator.result().collect()?)?
                }
                None => {
                    let digest = computed
                        .iter()
                        .find(|(oid, _)| oid == signer.digest_algorithm.algorithm())
                        .map(|(_, digest)| digest.as_slice())
                        .unwrap_or_default();
                    sign_digest(signer, Some(&self.generator.content_type), digest)?
                }
            };
            signer_infos.push(info);
        }
        tail.extend(Asn1SetOf::new(signer_infos).encode_to_vec(&EncodingOptions::DER)?);
        tail.extend([0, 0, 0, 0, 0, 0]);
        self.output.write_all(&tail).map_err(CmsError::Io)?;
        self.output.flush().map_err(CmsError::Io)
    }

    fn flush_segment(&mut self) -> Result<(), CmsError> {
        if !self.encapsulate || self.pending.is_empty() {
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

impl Write for SignedDataWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for (_, digest) in &mut self.digests {
            digest.try_update(buf).map_err(io::Error::other)?;
        }
        for calculator in self.direct.iter_mut().flatten() {
            calculator.write_all(buf)?;
        }
        if self.encapsulate {
            self.pending.extend_from_slice(buf);
            if self.pending.len() >= SEGMENT {
                self.flush_segment().map_err(io::Error::other)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

// RFC 5652 §5.1：有以 subjectKeyIdentifier 識別的簽署者，或內容不是 id-data 時是 3，否則是 1
fn version(generator: &CmsSignedDataGenerator) -> u64 {
    let key_identifier = generator
        .signers
        .iter()
        .any(|signer| matches!(signer.sid, SignerIdentifier::SubjectKeyIdentifier(_)));
    if key_identifier || ContentType::DATA != generator.content_type {
        3
    } else {
        1
    }
}

fn indefinite(out: &mut Vec<u8>, tag: u8) {
    out.extend([tag, 0x80]);
}
