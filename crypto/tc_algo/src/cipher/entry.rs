use core::fmt;

use tc_asn1::NamedOid;
use tc_zeroize::Zeroizing;

use super::AnyCipher;
use super::init_params::InitParams;
use super::table::specs::{AlgorithmSpec, ModeSpec, Need, PaddingSpec};
use crate::params::{AnyKeyParams, AnyParams};
use crate::{AlgoError, ErrorKind};

pub struct CipherEntry {
    // The canonical name, such as AES/CBC/PKCS7PADDING
    name: String,
    algorithm: &'static AlgorithmSpec,
    mode: &'static ModeSpec,
    padding: &'static PaddingSpec,
    oids: &'static [NamedOid],
}

impl CipherEntry {
    pub(super) fn new(
        algorithm: &'static AlgorithmSpec,
        mode: &'static ModeSpec,
        padding: &'static PaddingSpec,
        oids: &'static [NamedOid],
    ) -> Self {
        Self {
            name: format!(
                "{}/{}/{}",
                algorithm.names[0], mode.names[0], padding.names[0]
            ),
            algorithm,
            mode,
            padding,
            oids,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn cipher(&'static self) -> AnyCipher {
        AnyCipher::new(self)
    }

    pub(super) fn algorithm(&self) -> &'static AlgorithmSpec {
        self.algorithm
    }

    pub(super) fn mode(&self) -> &'static ModeSpec {
        self.mode
    }

    pub(super) fn padding(&self) -> &'static PaddingSpec {
        self.padding
    }

    pub(super) fn is(
        &self,
        algorithm: &AlgorithmSpec,
        mode: &ModeSpec,
        padding: &PaddingSpec,
    ) -> bool {
        core::ptr::eq(self.algorithm, algorithm)
            && core::ptr::eq(self.mode, mode)
            && core::ptr::eq(self.padding, padding)
    }

    // Checks the params against what this entry's mode needs and builds what the layers
    // underneath take: a secret key, and each operation field required, allowed or refused
    pub(super) fn init_params(&self, params: &AnyParams) -> Result<InitParams, AlgoError> {
        let AnyKeyParams::Secret(secret) = &params.key else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        let op = &params.op;
        check(self.mode.iv(), op.iv.is_some())?;
        check(self.mode.tag_len(), op.tag_len.is_some())?;
        check(self.mode.aad(), op.aad.is_some())?;
        Ok(InitParams {
            key: Zeroizing::new(secret.key.clone()),
            iv: op.iv.clone(),
            tag_len: op.tag_len,
            aad: op.aad.clone().unwrap_or_default(),
        })
    }
}

fn check(need: Need, present: bool) -> Result<(), AlgoError> {
    match (need, present) {
        (Need::Required, false) | (Need::Forbidden, true) => {
            Err(AlgoError::new(ErrorKind::InvalidParams))
        }
        _ => Ok(()),
    }
}

impl fmt::Debug for CipherEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherEntry")
            .field("name", &self.name)
            .field("oids", &self.oids)
            .finish_non_exhaustive()
    }
}

// The canonical name, followed by the OIDs when there are any, e.g.
// `AES/CBC/PKCS7PADDING  [id-aes128-CBC, id-aes192-CBC, id-aes256-CBC]`
impl fmt::Display for CipherEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
