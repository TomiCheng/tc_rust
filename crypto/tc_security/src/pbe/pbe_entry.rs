use std::fmt::{self, Display, Formatter};

use tc_asn1::NamedOid;
use tc_digest::TryDigest;
use tc_pbe::{
    OpenSslPbe, PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S1, Pkcs12,
    pkcs5_password_to_bytes, pkcs12_password_to_bytes,
};
use tc_zeroize::Zeroizing;

use crate::AnyError;
use crate::cipher::{self, AnyCipher};
use crate::digest;
use crate::mac::{self, AnyMac};
use crate::params::AnyParams;

/// 方案用哪種產生器，同 BC `PbeUtilities` 的 `AlgorithmType`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時，有些方案不在表裡")]
pub(super) enum Scheme {
    /// PKCS#5 v1（PBES1），密碼用 PKCS#5 的編碼。
    Pkcs5S1,
    /// PKCS#12，密碼用 UTF-16BE 加結尾的編碼。
    Pkcs12,
    /// OpenSSL 的 `EVP_BytesToKey`，密碼用 PKCS#5 的編碼，忽略迭代次數。
    OpenSsl,
}

/// 方案產生的是 cipher 的金鑰與 IV，還是 MAC 的金鑰。
#[derive(Clone, Copy, Debug)]
#[allow(dead_code, reason = "沒開對應的 digest、cipher 時，有些用途不在表裡")]
enum Purpose {
    Cipher {
        // cipher 工廠的名稱，例如 `"DES/CBC/PKCS7PADDING"`
        cipher: &'static str,
        key_bytes: usize,
        iv_bytes: usize,
        // DES 與 DESede 的金鑰同 BC 的 `FixDesParity` 設 odd parity
        des_parity: bool,
    },
    /// BC 的 `PBEwithHmac…`：MAC 金鑰與 digest 一樣長。
    Mac {
        // MAC 工廠的名稱，例如 `"HMAC-SHA1"`
        mac: &'static str,
    },
}

/// 一種 PBE 方案：產生器、digest，以及它給哪個 cipher 或 MAC 用。
#[derive(Clone, Copy, Debug)]
pub struct PbeEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    scheme: Scheme,
    digest: digest::Algorithm,
    purpose: Purpose,
}

impl PbeEntry {
    /// cipher 的方案。
    #[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時，表是空的")]
    #[allow(clippy::too_many_arguments, reason = "表的一列，欄位就是這些")]
    pub(super) const fn new_cipher(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        scheme: Scheme,
        digest: digest::Algorithm,
        cipher: &'static str,
        key_bytes: usize,
        iv_bytes: usize,
        des_parity: bool,
    ) -> Self {
        Self {
            names,
            oids,
            scheme,
            digest,
            purpose: Purpose::Cipher {
                cipher,
                key_bytes,
                iv_bytes,
                des_parity,
            },
        }
    }

    /// MAC 的方案；BC 的 `PBEwithHmac…` 都用 PKCS#12 的產生器。
    #[allow(dead_code, reason = "沒開對應的 digest 時，表是空的")]
    pub(super) const fn new_mac(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        digest: digest::Algorithm,
        mac: &'static str,
    ) -> Self {
        Self {
            names,
            oids,
            scheme: Scheme::Pkcs12,
            digest,
            purpose: Purpose::Mac { mac },
        }
    }

    /// 正式名稱，例如 `"PBEWITHSHAAND3-KEYTRIPLEDES-CBC"`。
    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    /// 方案的 cipher，同 BC 的 `PbeUtilities.CreateEngine`；MAC 的方案回傳 `None`。
    pub fn cipher(&self) -> Option<AnyCipher> {
        match self.purpose {
            Purpose::Cipher { cipher, .. } => Some(
                cipher::get_by_name(cipher)
                    .expect("a PBE scheme is listed only with its cipher's feature")
                    .cipher(),
            ),
            Purpose::Mac { .. } => None,
        }
    }

    /// 方案的 MAC，同 BC 的 `PbeUtilities.CreateEngine`；cipher 的方案回傳 `None`。
    pub fn mac(&self) -> Option<AnyMac> {
        match self.purpose {
            Purpose::Mac { mac } => Some(
                mac::get_by_name(mac)
                    .expect("a PBE scheme is listed only with its digest's feature")
                    .mac(),
            ),
            Purpose::Cipher { .. } => None,
        }
    }

    /// 由密碼、salt 與迭代次數產生參數，同 BC 的 `GenerateCipherParameters`：cipher 的方案是金鑰與
    /// IV（RC4 只有金鑰），MAC 的方案是與 digest 一樣長的金鑰。密碼依方案編碼；迭代次數 0 除了 OpenSSL 的方案都會
    /// 被拒絕。
    pub fn generate_cipher_params(
        &self,
        password: &str,
        salt: &[u8],
        iteration_count: usize,
    ) -> Result<AnyParams, AnyError> {
        let password = match self.scheme {
            Scheme::Pkcs12 => pkcs12_password_to_bytes(password, false),
            Scheme::Pkcs5S1 | Scheme::OpenSsl => pkcs5_password_to_bytes(password),
        };
        let mut generator = self
            .generator(&PbeParamsRef::new(&password, salt, iteration_count))
            .map_err(AnyError::new)?;
        match self.purpose {
            Purpose::Cipher {
                key_bytes,
                iv_bytes,
                des_parity,
                ..
            } => {
                let mut key = Zeroizing::new(vec![0; key_bytes]);
                let mut iv = vec![0; iv_bytes];
                generator
                    .derive_key_and_iv(&mut key, &mut iv)
                    .map_err(AnyError::new)?;
                #[cfg(any(feature = "des", feature = "desede"))]
                if des_parity {
                    tc_des::set_odd_parity(&mut key);
                }
                #[cfg(not(any(feature = "des", feature = "desede")))]
                let _ = des_parity;
                let params = AnyParams::new(std::mem::take(&mut *key));
                // RC4 這類沒有 IV 的 cipher 只拿金鑰，同 BC 的 `GenerateDerivedParameters("RC4", …)`
                Ok(if iv_bytes == 0 {
                    params
                } else {
                    params.with_iv(iv)
                })
            }
            Purpose::Mac { .. } => {
                let mut key = Zeroizing::new(vec![0; digest::get(self.digest).digest_size()]);
                generator.derive_mac_key(&mut key).map_err(AnyError::new)?;
                Ok(AnyParams::new(std::mem::take(&mut *key)))
            }
        }
    }

    /// 方案的產生器，已經以 `params` 初始化。
    fn generator(
        &self,
        params: &PbeParamsRef<'_>,
    ) -> Result<Box<dyn PbeGenerator<Error = PbeError>>, PbeError> {
        let digest = digest::get(self.digest);
        match self.scheme {
            Scheme::Pkcs5S1 => initialized(Pkcs5S1::new(digest), params),
            Scheme::Pkcs12 => initialized(Pkcs12::new(digest), params),
            Scheme::OpenSsl => initialized(OpenSslPbe::new(digest), params),
        }
    }
}

fn initialized<G>(
    mut generator: G,
    params: &PbeParamsRef<'_>,
) -> Result<Box<dyn PbeGenerator<Error = PbeError>>, PbeError>
where
    G: PbeGenerator<Error = PbeError>
        + for<'a> PbeGeneratorInit<PbeParamsRef<'a>, Error = PbeError>
        + 'static,
{
    generator.init(params)?;
    Ok(Box::new(generator))
}

/// 正式名稱，有 OID 時接在後面，例如 `PBEWITHSHAAND3-KEYTRIPLEDES-CBC  [pbeWithSHAAnd3-KeyTripleDES-CBC]`。
impl Display for PbeEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if let Some((first, rest)) = self.oids.split_first() {
            write!(f, "  [{}", first.name())?;
            for oid in rest {
                write!(f, ", {}", oid.name())?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}
