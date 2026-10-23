use rand::CryptoRng;
use tc_asn1::{
    Asn1Object, Asn1OctetString, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_pkcs::{Pbes2Params, Pbkdf2Params, Pkcs5Algorithm};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_buffered_cipher::BufferedCipher;
use tc_pbe::{PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S2, pkcs5_password_to_utf8_bytes};
use tc_zeroize::Zeroizing;

use crate::cipher::{self, AnyCipher, CipherEntry};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError, digest, generate};

/// PBES2（RFC 8018 §6.2）解讀好的參數：PBKDF2 的 salt、迭代次數與 PRF，以及加密方案的 cipher 與
/// IV，對應 BC `PbeUtilities` 處理 `id-PBES2` 的部分。
///
/// PRF 依 OID 從 digest 工廠取得，hmacWithSHA… 的 OID 對到 digest 本身，同 BC 的 `DigestUtilities`；
/// 加密方案依 OID 從 cipher 工廠取得，參數是 IV，所以 RC2 的 `RC2-CBC-Parameter` 還不支援。金鑰長度
/// 是 PBKDF2 參數的 keyLength，沒寫時是 cipher OID 的預設長度，同 BC 的 `GetDefaultKeySize`。
///
/// 密碼編成 UTF-8，同 RFC 8018 的建議與 OpenSSL；BC C# 取每個字元的低位元組，兩者只有 ASCII 的密碼
/// 一致。
#[derive(Clone, Debug)]
pub struct Pbes2 {
    params: Pbes2Params,
    cipher: &'static CipherEntry,
    digest: digest::Algorithm,
    salt: Vec<u8>,
    iteration_count: usize,
    key_bytes: usize,
    iv: Vec<u8>,
}

impl Pbes2 {
    /// 解讀 PBES2 的參數，同 BC 的 `CreateEngine(AlgorithmIdentifier)`。KDF 不是 PBKDF2 時回傳
    /// `UnknownPbe`，PRF 或 cipher 不認得時回傳 `UnknownDigest` 或 `UnknownCipher`，加密方案沒有 IV、
    /// 或 cipher 沒有預設金鑰長度時回傳 `InvalidPbeParams`。
    #[allow(
        unreachable_code,
        unused_variables,
        reason = "沒開任何 digest 時 digest::Algorithm 沒有值"
    )]
    pub fn from_params(params: &Pbes2Params) -> Result<Self, AnyError> {
        let kdf = params.key_derivation_func();
        if *kdf.algorithm() != Pkcs5Algorithm::PBKDF2 {
            return Err(AnyError::new(SecurityError::UnknownPbe));
        }
        let pbkdf2: Pbkdf2Params = reparse(kdf.parameters())?;
        let digest = digest::get_by_oid(pbkdf2.prf().algorithm())
            .map_err(AnyError::new)?
            .algorithm();

        let scheme = params.encryption_scheme();
        let cipher = cipher::get_by_oid(scheme.algorithm()).map_err(AnyError::new)?;
        let Some(Asn1Object::OctetString(iv)) = scheme.parameters() else {
            return Err(invalid());
        };
        let key_bytes = match pbkdf2.key_length() {
            Some(length) => to_usize(length)?,
            None => generate::get_by_oid(scheme.algorithm())
                .ok()
                .and_then(|entry| entry.default_strength())
                .map(|bits| bits / 8)
                .ok_or_else(invalid)?,
        };

        Ok(Self {
            params: params.clone(),
            cipher,
            digest,
            salt: pbkdf2.salt().as_bytes().to_vec(),
            iteration_count: to_usize(pbkdf2.iteration_count())?,
            key_bytes,
            iv: iv.as_bytes().to_vec(),
        })
    }

    /// 為加密產生參數，同 BC 的 `GenerateAlgorithmParameters(cipherOid, prfOid, salt,
    /// iterationCount, random)`：IV 是 cipher 一個區塊長的亂數，PRF 寫成 `prf` 加 NULL 參數，不寫
    /// keyLength。BC 只收 AES 的 CBC 與 CFB；這裡收 cipher 工廠認得、有預設金鑰長度的 OID。
    pub fn generate(
        cipher: &Asn1Oid,
        prf: &Asn1Oid,
        salt: &[u8],
        iteration_count: usize,
        rng: &mut dyn CryptoRng,
    ) -> Result<Self, AnyError> {
        let entry = cipher::get_by_oid(cipher).map_err(AnyError::new)?;
        let mut iv = vec![0; entry.cipher().block_size()];
        rng.fill_bytes(&mut iv);
        let pbkdf2 = Pbkdf2Params::new(Asn1OctetString::new(salt), (iteration_count as u64).into())
            .map_err(AnyError::new)?
            .with_prf(AlgorithmIdentifier::with_null(prf.clone()));
        let params = Pbes2Params::new(
            AlgorithmIdentifier::with_parameters(Pkcs5Algorithm::PBKDF2.oid(), to_object(&pbkdf2)?),
            AlgorithmIdentifier::with_parameters(cipher.clone(), Asn1OctetString::new(&iv)),
        );
        Self::from_params(&params)
    }

    /// 寫進 `AlgorithmIdentifier` 的 PBES2 參數。
    pub fn params(&self) -> &Pbes2Params {
        &self.params
    }

    /// 加密方案的 cipher，同 BC 的 `CreateEngine`。
    pub fn cipher(&self) -> AnyCipher {
        self.cipher.cipher()
    }

    /// 由密碼以 PBKDF2 推出 cipher 的金鑰，加上參數裡的 IV，同 BC 的 `GenerateCipherParameters`。
    pub fn generate_cipher_params(&self, password: &str) -> Result<AnyParams, AnyError> {
        let password = pkcs5_password_to_utf8_bytes(password);
        let mut generator = Pkcs5S2::new(digest::get(self.digest));
        generator
            .init(&PbeParamsRef::new(
                &password,
                &self.salt,
                self.iteration_count,
            ))
            .map_err(AnyError::new)?;
        let mut key = Zeroizing::new(vec![0; self.key_bytes]);
        generator.derive_key(&mut key).map_err(AnyError::new)?;
        Ok(AnyParams::new(std::mem::take(&mut *key)).with_iv(self.iv.clone()))
    }
}

fn invalid() -> AnyError {
    AnyError::new(SecurityError::InvalidPbeParams)
}

fn to_usize(value: &tc_asn1::Asn1Integer) -> Result<usize, AnyError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(invalid)
}

/// `AlgorithmIdentifier` 的參數是沒有 schema 的 `Asn1Object`，重新編碼再照 `T` 解讀。
fn reparse<T: Decode>(parameters: Option<&Asn1Object>) -> Result<T, AnyError> {
    let der = parameters
        .ok_or_else(invalid)?
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
