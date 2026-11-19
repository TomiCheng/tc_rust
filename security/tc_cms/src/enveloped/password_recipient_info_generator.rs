use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::Algo;
use tc_algo::params::cipher::KeyWithIvOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, Asn1SequenceOf};
use tc_asn1_cms::recipient::{PasswordRecipientInfo, RecipientInfo};
use tc_asn1_pkcs::{Pbkdf2Params, Pkcs5Algorithm};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::X509Operator;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::{PWRI_KEK, content_key_length, rfc3211_wrapper};
use crate::der::convert;
use crate::enveloped::RecipientInfoGenerator;
use crate::enveloped::password_key::derive;

// BC 的 PasswordRecipientInfoGenerator：以 PBKDF2 從密碼推出 KEK，再以 RFC 3211 的 PWRI-KEK 包住
// 內容金鑰。kek_algorithm 是 AES-CBC 或 DES-EDE3-CBC 的 OID，KEK 是它的金鑰長度；PRF 是
// hmacWithSHA1，參數裡不寫，同 BC 的 Pkcs5Scheme2UTF8PBEKey。密碼編成 UTF-8
pub struct PasswordRecipientInfoGenerator {
    password: Zeroizing<Vec<u8>>,
    kek_algorithm: Asn1Oid,
    salt: Vec<u8>,
    iterations: usize,
}

impl PasswordRecipientInfoGenerator {
    pub fn new(password: &str, kek_algorithm: Asn1Oid, salt: Vec<u8>, iterations: usize) -> Self {
        Self {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            kek_algorithm,
            salt,
            iterations,
        }
    }
}

impl RecipientInfoGenerator for PasswordRecipientInfoGenerator {
    fn generate(
        &self,
        algo: &dyn Algo,
        _x509: &dyn X509Operator,
        content_key: &[u8],
    ) -> Result<RecipientInfo, CmsError> {
        let wrapper = rfc3211_wrapper(&self.kek_algorithm)?;
        let pbkdf2 = Pbkdf2Params::new(
            Asn1OctetString::new(&self.salt),
            (self.iterations as u64).into(),
        )?;
        let kek = derive(
            algo,
            &pbkdf2,
            &self.password,
            content_key_length(&self.kek_algorithm)?,
        )?;
        let block = algo.cipher().get_by_oid(&self.kek_algorithm)?.block_size();
        let mut iv = vec![0; block];
        UnwrapErr(SysRng).fill_bytes(&mut iv);
        let wrapped = algo.wrap().wrap_by_name(
            wrapper,
            &KeyWithIvOwned::new(kek.to_vec(), iv.clone()),
            content_key,
        )?;

        let kek_params = Asn1SequenceOf::new(vec![
            Asn1Object::Oid(self.kek_algorithm.clone()),
            Asn1Object::OctetString(Asn1OctetString::new(&iv)),
        ]);
        let info = PasswordRecipientInfo::new(
            AlgorithmIdentifier::with_parameters(
                PWRI_KEK.parse()?,
                convert::<_, Asn1Object>(&kek_params)?,
            ),
            Asn1OctetString::new(&wrapped),
        )
        .with_key_derivation_algorithm(AlgorithmIdentifier::with_parameters(
            Pkcs5Algorithm::PBKDF2.oid(),
            convert::<_, Asn1Object>(&pbkdf2)?,
        ));
        Ok(RecipientInfo::Password(info))
    }
}
