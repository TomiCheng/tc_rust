use std::any::Any;

use tc_algo::params::kdf::PbeParamsOwned;
use tc_algo::{Algo, Params};
use tc_asn1_pkcs::Pbkdf2Params;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::pbkdf2;

// 解開 Password 收件人用的密碼，同 BC 的 CmsPbeKey；salt 與迭代次數取自訊息。編成 UTF-8
pub struct PasswordKey {
    password: Zeroizing<Vec<u8>>,
}

impl PasswordKey {
    pub fn new(password: &str) -> Self {
        Self {
            password: Zeroizing::new(password.as_bytes().to_vec()),
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.password
    }
}

impl Params for PasswordKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// PBKDF2 推出 length bytes 的 KEK；參數裡的 keyLength 優先
pub(crate) fn derive(
    algo: &dyn Algo,
    params: &Pbkdf2Params,
    password: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CmsError> {
    let length = match params.key_length() {
        Some(key_length) => to_usize(key_length)?,
        None => length,
    };
    let mut kdf = algo.kdf().get_by_name(pbkdf2(params.prf().algorithm())?)?;
    kdf.init(&PbeParamsOwned::new(
        password.to_vec(),
        params.salt().as_bytes().to_vec(),
        to_usize(params.iteration_count())?,
    ))?;
    let mut key = Zeroizing::new(vec![0; length]);
    kdf.generate_bytes(&mut key)?;
    Ok(key)
}

fn to_usize(value: &tc_asn1::Asn1Integer) -> Result<usize, CmsError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CmsError::UnknownAlgorithm)
}
