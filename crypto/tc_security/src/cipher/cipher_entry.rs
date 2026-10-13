use std::fmt::{self, Display, Formatter};

use crate::cipher::table::create_cipher;
use crate::cipher::{Algorithm, AnyCipher, Mode, Padding};
use tc_asn1::NamedOid;

/// 一個合法的「演算法/模式/padding」組合，在第一次查詢時由三張小表展開。
#[derive(Clone, Debug)]
pub struct CipherEntry {
    algo: Algorithm,
    // stream cipher 沒有模式與 padding
    mode: Option<Mode>,
    padding: Option<Padding>,
    name: String,
    oids: &'static [NamedOid],
}

impl CipherEntry {
    pub(super) fn new(
        algo: Algorithm,
        mode: Option<Mode>,
        padding: Option<Padding>,
        name: String,
        oids: &'static [NamedOid],
    ) -> Self {
        Self {
            algo,
            mode,
            padding,
            name,
            oids,
        }
    }
    pub fn algo(&self) -> Algorithm {
        self.algo
    }
    // block cipher 一定有；stream cipher 是 None
    pub fn mode(&self) -> Option<Mode> {
        self.mode
    }
    pub fn padding(&self) -> Option<Padding> {
        self.padding
    }
    /// 正式名稱，例如 `"AES/CBC/PKCS7PADDING"`。
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }
    pub fn cipher(&self) -> AnyCipher {
        create_cipher(self.algo, self.mode, self.padding)
    }
}

/// 正式名稱，有 OID 時接在後面，例如
/// `AES/CCM/NOPADDING  [id-aes128-CCM, id-aes192-CCM, id-aes256-CCM]`。
impl Display for CipherEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
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
