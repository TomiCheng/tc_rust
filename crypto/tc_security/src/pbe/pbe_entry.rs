use std::fmt::{self, Display, Formatter};

use tc_asn1::NamedOid;
use tc_pbe::{
    OpenSslPbe, PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S1, Pkcs12,
    pkcs5_password_to_bytes, pkcs12_password_to_bytes,
};
use tc_zeroize::Zeroizing;

use crate::AnyError;
use crate::cipher::{self, AnyCipher};
use crate::digest;
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

/// 一種 PBE 方案：產生器、digest、cipher，以及金鑰與 IV 的長度。
#[derive(Clone, Copy, Debug)]
pub struct PbeEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    scheme: Scheme,
    digest: digest::Algorithm,
    // cipher 工廠的名稱，例如 `"DES/CBC/PKCS7PADDING"`
    cipher: &'static str,
    key_bytes: usize,
    iv_bytes: usize,
    // DES 與 DESede 的金鑰同 BC 的 `FixDesParity` 設 odd parity
    #[allow(dead_code, reason = "des 與 desede 都關掉時沒有人讀")]
    des_parity: bool,
}

impl PbeEntry {
    #[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時，表是空的")]
    #[allow(clippy::too_many_arguments, reason = "表的一列，欄位就是這些")]
    pub(super) const fn new(
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
            cipher,
            key_bytes,
            iv_bytes,
            des_parity,
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

    /// 方案的 cipher，同 BC 的 `PbeUtilities.CreateEngine`。
    pub fn cipher(&self) -> AnyCipher {
        cipher::get_by_name(self.cipher)
            .expect("a PBE scheme is listed only with its cipher's feature")
            .cipher()
    }

    /// 由密碼、salt 與迭代次數產生 cipher 的金鑰與 IV，同 BC 的 `GenerateCipherParameters`；
    /// 密碼依方案編碼。迭代次數 0 除了 OpenSSL 的方案都會被拒絕。
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
        let params = PbeParamsRef::new(&password, salt, iteration_count);
        let digest = digest::get(self.digest);
        let mut key = Zeroizing::new(vec![0; self.key_bytes]);
        let mut iv = vec![0; self.iv_bytes];
        match self.scheme {
            Scheme::Pkcs5S1 => derive(Pkcs5S1::new(digest), &params, &mut key, &mut iv),
            Scheme::Pkcs12 => derive(Pkcs12::new(digest), &params, &mut key, &mut iv),
            Scheme::OpenSsl => derive(OpenSslPbe::new(digest), &params, &mut key, &mut iv),
        }
        .map_err(AnyError::new)?;
        #[cfg(any(feature = "des", feature = "desede"))]
        if self.des_parity {
            tc_des::set_odd_parity(&mut key);
        }
        Ok(AnyParams::new(std::mem::take(&mut *key)).with_iv(iv))
    }
}

fn derive<G>(
    mut generator: G,
    params: &PbeParamsRef<'_>,
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<(), PbeError>
where
    G: PbeGenerator<Error = PbeError>
        + for<'a> PbeGeneratorInit<PbeParamsRef<'a>, Error = PbeError>,
{
    generator.init(params)?;
    generator.derive_key_and_iv(key, iv)
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
