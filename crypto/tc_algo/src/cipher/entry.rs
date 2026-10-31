use core::fmt;

use tc_asn1::NamedOid;
use tc_zeroize::Zeroizing;

use super::AnyCipher;
use super::init_params::{InitParams, SymmetricParams};
use super::table::specs::{AlgorithmSpec, ModeSpec, Need, PaddingSpec};
#[cfg(feature = "rsa")]
use super::table::specs::{AsymmetricPaddingSpec, AsymmetricSpec};
use crate::params::{AnyKeyParams, AnyParams};
use crate::{AlgoError, ErrorKind};

pub struct CipherEntry {
    // The canonical name, such as AES/CBC/PKCS7PADDING
    name: String,
    kind: Kind,
    oids: &'static [NamedOid],
}

// What the entry is made of, one variant per kind of cipher
pub(super) enum Kind {
    Block {
        algorithm: &'static AlgorithmSpec,
        mode: &'static ModeSpec,
        padding: &'static PaddingSpec,
    },
    #[cfg(feature = "rsa")]
    Asymmetric {
        algorithm: &'static AsymmetricSpec,
        mode: &'static str,
        padding: &'static AsymmetricPaddingSpec,
    },
}

impl CipherEntry {
    pub(super) fn new(kind: Kind, oids: &'static [NamedOid]) -> Self {
        let name = match &kind {
            Kind::Block {
                algorithm,
                mode,
                padding,
            } => format!(
                "{}/{}/{}",
                algorithm.names[0], mode.names[0], padding.names[0]
            ),
            #[cfg(feature = "rsa")]
            Kind::Asymmetric {
                algorithm,
                mode,
                padding,
            } => format!("{}/{}/{}", algorithm.names[0], mode, padding.names[0]),
        };
        Self { name, kind, oids }
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

    pub(super) fn kind(&self) -> &Kind {
        &self.kind
    }

    // Checks the params against what this entry needs and builds what the layers underneath
    // take, so that nothing is filled in or dropped silently
    pub(super) fn init_params(&self, params: &AnyParams) -> Result<InitParams, AlgoError> {
        let op = &params.op;
        match &self.kind {
            // A secret key, and each operation field required, allowed or refused by the mode
            Kind::Block { mode, .. } => {
                let AnyKeyParams::Secret(secret) = &params.key else {
                    return Err(AlgoError::new(ErrorKind::InvalidParams));
                };
                check(mode.iv(), op.iv.is_some())?;
                check(mode.tag_len(), op.tag_len.is_some())?;
                check(mode.aad(), op.aad.is_some())?;
                Ok(InitParams::Symmetric(SymmetricParams {
                    key: Zeroizing::new(secret.key.clone()),
                    iv: op.iv.clone(),
                    tag_len: op.tag_len,
                    aad: op.aad.clone().unwrap_or_default(),
                }))
            }
            // A key of the algorithm, and no operation field at all
            #[cfg(feature = "rsa")]
            Kind::Asymmetric { algorithm, .. } => {
                check(Need::Forbidden, op.iv.is_some())?;
                check(Need::Forbidden, op.tag_len.is_some())?;
                check(Need::Forbidden, op.aad.is_some())?;
                (algorithm.key)(&params.key).ok_or(AlgoError::new(ErrorKind::InvalidParams))
            }
        }
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
