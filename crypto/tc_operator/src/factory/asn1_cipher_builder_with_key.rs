use std::io;

use tc_asn1::{Asn1OctetString, Asn1Oid};
use tc_asn1_cms::params::{CcmParameters, GcmParameters};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_buffered_cipher::{BufferedCipherInit, CipherDirection};
use tc_security::SecurityError;
use tc_security::cipher::{self, AnyCipher, Mode};
use tc_security::generate::{self, KeyGenParams};
use tc_security::params::{self, AnyParams};

use super::der::to_object;
use crate::calculator::BufferedCipherWriter;
use crate::{CipherBuilder, CipherBuilderWithKey, OperatorError};

pub struct Asn1CipherBuilderWithKey {
    algorithm: AlgorithmIdentifier,
    key: Vec<u8>,
    params: AnyParams,
}

impl Asn1CipherBuilderWithKey {
    pub fn new(encryption_oid: &Asn1Oid, key_size: Option<usize>) -> Result<Self, OperatorError> {
        let mut generator = generate::get_by_oid(encryption_oid)?.generator();
        if let Some(strength) = key_size {
            generator.init(&KeyGenParams::Basic { strength })?;
        }
        let key = generator.generate_key()?;
        let AnyParams::Key { key: key_bytes } = &key else {
            return Err(SecurityError::UnknownCipher.into());
        };
        let key_bytes = key_bytes.clone();
        let params = params::get_by_oid(encryption_oid)?
            .generator(key)
            .generate()?;
        let mode = cipher::get_by_oid(encryption_oid)?.mode();
        Ok(Self {
            algorithm: algorithm_identifier(encryption_oid, mode, &params)?,
            key: key_bytes,
            params,
        })
    }
}

fn algorithm_identifier(
    oid: &Asn1Oid,
    mode: Option<Mode>,
    params: &AnyParams,
) -> Result<AlgorithmIdentifier, OperatorError> {
    match params {
        AnyParams::WithIv { parameters, iv } => match **parameters {
            AnyParams::Key { .. } => Ok(AlgorithmIdentifier::with_parameters(
                oid.clone(),
                Asn1OctetString::new(iv),
            )),
            _ => Err(SecurityError::UnknownCipher.into()),
        },
        AnyParams::Aead {
            mac_size, nonce, ..
        } => {
            let nonce = Asn1OctetString::new(nonce);
            let icv_len = (mac_size / 8) as u8;
            let parameters = match mode {
                Some(Mode::Ccm) => to_object(&CcmParameters::new(nonce, icv_len)?)?,
                _ => to_object(&GcmParameters::new(nonce, icv_len)?)?,
            };
            Ok(AlgorithmIdentifier::with_parameters(
                oid.clone(),
                parameters,
            ))
        }
        AnyParams::Key { .. } => Ok(AlgorithmIdentifier::with_null(oid.clone())),
        _ => Err(SecurityError::UnknownCipher.into()),
    }
}

impl CipherBuilder for Asn1CipherBuilderWithKey {
    type Writer<W: io::Write> = BufferedCipherWriter<AnyCipher, W>;
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn build_cipher<W: io::Write>(
        &self,
        output: W,
    ) -> Result<BufferedCipherWriter<AnyCipher, W>, OperatorError> {
        let mut cipher = cipher::get_by_oid(self.algorithm.algorithm())?.cipher();
        cipher.init(CipherDirection::Encrypt, &self.params)?;
        Ok(BufferedCipherWriter::new(cipher, output))
    }
}

impl CipherBuilderWithKey for Asn1CipherBuilderWithKey {
    fn key(&self) -> &[u8] {
        &self.key
    }
}
