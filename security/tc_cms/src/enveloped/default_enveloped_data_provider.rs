use std::mem;

use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::Params;
use tc_algo::params::cipher::KeyWithIvOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid};
use tc_asn1_cms::content::{EncryptedContentInfo, EnvelopedData};
use tc_asn1_cms::recipient::RecipientInfo;
use tc_asn1_pkcs::{Pkcs1Algorithm, RsaesOaepParams};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::{RSA_ENCRYPTION, RSAES_OAEP, content_key_length, equivalent, oaep_digest};
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::convert;
use crate::enveloped::{
    CmsEnvelopedData, CmsEnvelopedDataGenerator, EnvelopedDataProvider, RecipientInformation,
};

impl EnvelopedDataProvider for DefaultCmsOperator {
    fn generate(
        &self,
        generator: &CmsEnvelopedDataGenerator,
        content: &[u8],
        encryption: &Asn1Oid,
    ) -> Result<CmsEnvelopedData, CmsError> {
        let mut key = Zeroizing::new(random(content_key_length(encryption)?));
        let block = self.algo.cipher().get_by_oid(encryption)?.block_size();
        let iv = random(block);
        let encrypted = self.algo.cipher().encrypt_by_oid(
            encryption,
            &KeyWithIvOwned::new(key.to_vec(), iv.clone()),
            content,
        )?;

        let mut recipients = Vec::new();
        for recipient in &generator.recipients {
            recipients.push(recipient.generate(self.algo.as_ref(), self.x509.as_ref(), &key)?);
        }
        mem::take(&mut *key);

        let algorithm = AlgorithmIdentifier::with_parameters(
            encryption.clone(),
            Asn1Object::OctetString(Asn1OctetString::new(&iv)),
        );
        let info = EncryptedContentInfo::new(generator.content_type.clone(), algorithm)
            .with_encrypted_content(Asn1OctetString::new(&encrypted));
        Ok(CmsEnvelopedData::new(EnvelopedData::new(recipients, info)))
    }

    fn decrypt(
        &self,
        enveloped: &CmsEnvelopedData,
        recipient: &RecipientInformation,
        private_key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError> {
        let RecipientInfo::KeyTrans(info) = recipient.recipient_info() else {
            return Err(CmsError::UnknownAlgorithm);
        };
        let name = key_trans_cipher(info.key_encryption_algorithm())?;
        let key = Zeroizing::new(self.algo.cipher().decrypt_by_name(
            &name,
            private_key,
            info.encrypted_key().as_bytes(),
        )?);

        let encrypted = enveloped.enveloped_data().encrypted_content_info();
        let algorithm = encrypted.content_encryption_algorithm();
        if key.len() != content_key_length(algorithm.algorithm())? {
            return Err(CmsError::InvalidKey);
        }
        let Some(Asn1Object::OctetString(iv)) = algorithm.parameters() else {
            return Err(CmsError::UnknownAlgorithm);
        };
        let sealed = encrypted
            .encrypted_content()
            .ok_or(CmsError::MissingContent)?;
        Ok(Zeroizing::new(self.algo.cipher().decrypt_by_oid(
            algorithm.algorithm(),
            &KeyWithIvOwned::new(key.to_vec(), iv.as_bytes().to_vec()),
            sealed.as_bytes(),
        )?))
    }
}

// 金鑰加密演算法對到 tc_algo 的 RSA 列：rsaEncryption 是 PKCS#1 v1.5，id-RSAES-OAEP 依參數，
// MGF1 要與 hash 同一個摘要、label 要是空的
fn key_trans_cipher(algorithm: &AlgorithmIdentifier) -> Result<String, CmsError> {
    let dotted = algorithm.algorithm().to_string();
    if dotted == RSA_ENCRYPTION {
        return Ok("RSA//PKCS1PADDING".to_string());
    }
    if dotted != RSAES_OAEP {
        return Err(CmsError::UnknownAlgorithm);
    }
    let params: RsaesOaepParams = match algorithm.parameters() {
        Some(params) => convert(params)?,
        None => RsaesOaepParams::default_params(),
    };
    let hash = params.hash_algorithm();
    let mgf = params.mask_gen_algorithm();
    let mgf_hash: Option<AlgorithmIdentifier> =
        mgf.parameters().and_then(|params| convert(params).ok());
    if *mgf.algorithm() != Pkcs1Algorithm::MGF1
        || !mgf_hash.is_some_and(|mgf_hash| equivalent(&mgf_hash, hash))
        || *params.p_source_algorithm() != RsaesOaepParams::p_specified_empty()
    {
        return Err(CmsError::UnknownAlgorithm);
    }
    Ok(format!(
        "RSA//OAEPWITH{}ANDMGF1PADDING",
        oaep_digest(hash.algorithm())?
    ))
}

fn random(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    UnwrapErr(SysRng).fill_bytes(&mut bytes);
    bytes
}
