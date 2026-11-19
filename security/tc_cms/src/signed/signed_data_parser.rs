use std::io::{self, BufReader, Read, Write};

use tc_algo::Algo;
use tc_algo::digest::Digest;
use tc_asn1::io::Asn1Reader;
use tc_asn1::{Asn1Any, Asn1Integer, Asn1Oid, Asn1SetOf, Encode, EncodingOptions};
use tc_asn1_cms::content::{ContentType, SignedData};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{decode_all, length};
use crate::signed::CmsSignedData;
use crate::stream::{copy_octets, options, required};

// BC 的 CmsSignedDataParser：內容邊讀邊寫到 content 並算摘要，其餘的小欄位讀進記憶體。給出的
// CmsSignedData 沒有內容，帶著算好的摘要，verify 由摘要驗證；不帶 signed attributes 的簽署者
// 要整份內容，驗證時是 MissingContent。detached 時內容從 detached 讀
pub(crate) fn parse(
    algo: &dyn Algo,
    input: &mut dyn Read,
    content: &mut dyn Write,
    detached: Option<&mut dyn Read>,
) -> Result<CmsSignedData, CmsError> {
    let mut reader = Asn1Reader::new(BufReader::new(input), options());
    let mut info = reader
        .read_sequence()
        .map_err(CmsError::Io)?
        .ok_or(CmsError::UnexpectedContentType)?;
    let content_type: Asn1Oid = info
        .read_value()
        .map_err(CmsError::Io)?
        .ok_or(CmsError::UnexpectedContentType)?;
    if ContentType::SIGNED_DATA != content_type {
        return Err(CmsError::UnexpectedContentType);
    }
    let mut explicit = info
        .read_constructed(&[0xa0])
        .map_err(CmsError::Io)?
        .ok_or(CmsError::UnexpectedContentType)?;
    let mut signed = explicit
        .read_sequence()
        .map_err(CmsError::Io)?
        .ok_or(CmsError::UnexpectedContentType)?;

    let version: Asn1Integer = required(signed.read_value())?;
    let algorithms: Asn1SetOf<AlgorithmIdentifier> = required(signed.read_value())?;
    let mut digests = Vec::new();
    for algorithm in algorithms.members() {
        let oid = algorithm.algorithm();
        if !digests
            .iter()
            .any(|(known, _): &(Asn1Oid, Box<dyn Digest>)| known == oid)
        {
            digests.push((oid.clone(), algo.digest().get_by_oid(oid)?));
        }
    }

    let encapsulated_type: Asn1Oid;
    {
        let mut encapsulated = signed
            .read_sequence()
            .map_err(CmsError::Io)?
            .ok_or(CmsError::UnexpectedContentType)?;
        encapsulated_type = required(encapsulated.read_value())?;
        let mut sink = DigestingSink {
            digests: &mut digests,
            content,
        };
        if let Some(mut explicit) = encapsulated
            .read_constructed(&[0xa0])
            .map_err(CmsError::Io)?
        {
            copy_octets(&mut explicit, &mut sink)?;
        }
        if let Some(detached) = detached {
            io::copy(detached, &mut sink).map_err(CmsError::Io)?;
        }
    }

    // 剩下的 certificates、crls 與 signerInfos 整個讀進來
    let mut tail = Vec::new();
    while let Some(element) = signed.read_value::<Asn1Any>().map_err(CmsError::Io)? {
        tail.extend_from_slice(element.raw());
    }

    // 以讀到的欄位重組一份沒有 eContent 的 SignedData，交給 tc_asn1_cms 解讀
    let mut fields = Vec::new();
    fields.extend(version.encode_to_vec(&EncodingOptions::DER)?);
    fields.extend(algorithms.encode_to_vec(&EncodingOptions::DER)?);
    let encapsulated = encapsulated_type.encode_to_vec(&EncodingOptions::DER)?;
    fields.push(0x30);
    length(&mut fields, encapsulated.len());
    fields.extend(encapsulated);
    fields.extend(tail);
    let mut der = vec![0x30];
    length(&mut der, fields.len());
    der.extend(fields);
    let signed_data: SignedData = decode_all(&der)?;

    let mut computed = Vec::new();
    for (oid, mut digest) in digests {
        computed.push((oid, digest.finalize()?));
    }
    Ok(CmsSignedData::with_digests(signed_data, computed))
}

struct DigestingSink<'a> {
    digests: &'a mut Vec<(Asn1Oid, Box<dyn Digest>)>,
    content: &'a mut dyn Write,
}

impl Write for DigestingSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for (_, digest) in self.digests.iter_mut() {
            digest.try_update(buf).map_err(io::Error::other)?;
        }
        self.content.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.content.flush()
    }
}
