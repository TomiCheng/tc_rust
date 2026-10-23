use tc_asn1::{
    Asn1Integer, Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_pkcs::{
    EncryptedPrivateKeyInfo, PbeParameter, Pbes2Params, Pkcs5Algorithm, PrivateKeyInfo,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::decode::decode_all;
use super::{private_key_from_info, private_key_to_der};
use crate::cipher::{self, AnyCipher};
use crate::params::AnyParams;
use crate::pbe::{self, PbeEntry, Pbes2};
use crate::{AnyError, SecurityError};

/// 加密私鑰的方案，對應 BC `EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo` 的兩種
/// 多載。
#[derive(Clone, Copy, Debug)]
pub enum KeyEncryption<'a> {
    /// PBE 工廠裡 cipher 的方案，例如 `PBEWITHSHAAND3-KEYTRIPLEDES-CBC`；參數寫成 `PBEParameter`，
    /// 所以方案要有 OID。
    Scheme {
        entry: &'static PbeEntry,
        salt: &'a [u8],
        iteration_count: usize,
    },
    /// PBES2，參數由 [`Pbes2::generate`] 產生。
    Pbes2(&'a Pbes2),
}

/// 私鑰轉成 PKCS#8 後以密碼加密，同 BC 的 `EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo`。
/// MAC 的方案與沒有 OID 的方案回傳 `UnknownPbe`。
pub fn encrypted_private_key_info(
    key: &AnyParams,
    password: &str,
    encryption: &KeyEncryption<'_>,
) -> Result<EncryptedPrivateKeyInfo, AnyError> {
    let (algorithm, mut cipher, params) = match *encryption {
        KeyEncryption::Scheme {
            entry,
            salt,
            iteration_count,
        } => {
            let (Some(oid), Some(cipher)) = (entry.oids().first(), entry.cipher()) else {
                return Err(AnyError::new(SecurityError::UnknownPbe));
            };
            let parameter = PbeParameter::new(
                Asn1OctetString::new(salt),
                Asn1Integer::from(iteration_count as u64),
            )
            .map_err(AnyError::new)?;
            let algorithm = AlgorithmIdentifier::with_parameters(oid.oid(), to_object(&parameter)?);
            let params = entry.generate_cipher_params(password, salt, iteration_count)?;
            (algorithm, cipher, params)
        }
        KeyEncryption::Pbes2(pbes2) => {
            let algorithm = AlgorithmIdentifier::with_parameters(
                Pkcs5Algorithm::PBES2.oid(),
                to_object(pbes2.params())?,
            );
            (
                algorithm,
                pbes2.cipher(),
                pbes2.generate_cipher_params(password)?,
            )
        }
    };
    let plain = private_key_to_der(key)?;
    let sealed = cipher::encrypt(&mut cipher, &params, &plain)?;
    Ok(EncryptedPrivateKeyInfo::new(
        algorithm,
        Asn1OctetString::new(&sealed),
    ))
}

/// 私鑰轉成加密的 PKCS#8 的 DER，同 BC 的 `PrivateKeyFactory.EncryptKey`。
pub fn private_key_to_encrypted_der(
    key: &AnyParams,
    password: &str,
    encryption: &KeyEncryption<'_>,
) -> Result<Vec<u8>, AnyError> {
    encrypted_private_key_info(key, password, encryption)?
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(AnyError::new)
}

/// 以密碼解開 `EncryptedPrivateKeyInfo`，同 BC 的 `PrivateKeyInfoFactory.CreatePrivateKeyInfo(passPhrase,
/// encInfo)`：`id-PBES2` 交給 [`Pbes2`]，其餘的 OID 從 PBE 工廠找方案，參數是 `PBEParameter`。
/// 密碼錯誤時通常是 cipher 的 padding 錯誤，少數情況是解出的 bytes 不是 `PrivateKeyInfo`。
pub fn decrypt_private_key_info(
    password: &str,
    info: &EncryptedPrivateKeyInfo,
) -> Result<PrivateKeyInfo, AnyError> {
    let algorithm = info.encryption_algorithm();
    let (mut cipher, params): (AnyCipher, AnyParams) = if *algorithm.algorithm()
        == Pkcs5Algorithm::PBES2
    {
        let pbes2 = Pbes2::from_params(&reparse::<Pbes2Params>(algorithm.parameters())?)?;
        (pbes2.cipher(), pbes2.generate_cipher_params(password)?)
    } else {
        let entry = pbe::get_by_oid(algorithm.algorithm()).map_err(AnyError::new)?;
        let cipher = entry
            .cipher()
            .ok_or_else(|| AnyError::new(SecurityError::UnknownPbe))?;
        let parameter: PbeParameter = reparse(algorithm.parameters())?;
        let iteration_count = u64::try_from(parameter.iteration_count())
            .ok()
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| AnyError::new(SecurityError::InvalidPbeParams))?;
        let params =
            entry.generate_cipher_params(password, parameter.salt().as_bytes(), iteration_count)?;
        (cipher, params)
    };
    let plain = Zeroizing::new(cipher::decrypt(
        &mut cipher,
        &params,
        info.encrypted_data().as_bytes(),
    )?);
    decode_all(&plain)
}

/// 加密的 PKCS#8 的 DER 以密碼解開成私鑰，同 BC 的 `PrivateKeyFactory.DecryptKey`。
pub fn private_key_from_encrypted_der(password: &str, der: &[u8]) -> Result<AnyParams, AnyError> {
    private_key_from_info(&decrypt_private_key_info(password, &decode_all(der)?)?)
}

/// `AlgorithmIdentifier` 的參數是沒有 schema 的 `Asn1Object`，重新編碼再照 `T` 解讀。
fn reparse<T: Decode>(parameters: Option<&Asn1Object>) -> Result<T, AnyError> {
    let der = parameters
        .ok_or_else(|| AnyError::new(SecurityError::InvalidPbeParams))?
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(AnyError::new)?;
    T::decode(&der, &DecodingOptions::default())
        .map(|(_, value)| value)
        .map_err(AnyError::new)
}

fn to_object<T: Encode>(value: &T) -> Result<Asn1Object, AnyError> {
    let der = value
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(AnyError::new)?;
    Asn1Object::decode(&der, &DecodingOptions::default())
        .map(|(_, object)| object)
        .map_err(AnyError::new)
}
