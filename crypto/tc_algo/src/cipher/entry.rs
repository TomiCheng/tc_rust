use core::fmt;

use tc_asn1::NamedOid;
use tc_zeroize::Zeroizing;

use super::AnyCipher;
use super::init_params::{InitParams, SymmetricParams};
use super::table::specs::{AlgorithmSpec, ModeSpec, Need, PaddingSpec, StreamSpec};
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
use super::table::specs::{AsymmetricPaddingSpec, AsymmetricSpec};
#[cfg(feature = "sm2")]
use super::table::specs::{MessageModeSpec, MessageSpec};
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
    // The name is the algorithm alone, as in Bouncy Castle
    Stream {
        algorithm: &'static StreamSpec,
    },
    #[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
    Asymmetric {
        algorithm: &'static AsymmetricSpec,
        mode: &'static str,
        padding: &'static AsymmetricPaddingSpec,
    },
    #[cfg(feature = "sm2")]
    Message {
        algorithm: &'static MessageSpec,
        mode: &'static MessageModeSpec,
    },
}

impl CipherEntry {
    pub(super) fn new(kind: Kind, oids: &'static [NamedOid]) -> Self {
        let name = match &kind {
            Kind::Stream { algorithm } => algorithm.names[0].to_string(),
            Kind::Block {
                algorithm,
                mode,
                padding,
            } => format!(
                "{}/{}/{}",
                algorithm.names[0], mode.names[0], padding.names[0]
            ),
            #[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
            Kind::Asymmetric {
                algorithm,
                mode,
                padding,
            } => format!("{}/{}/{}", algorithm.names[0], mode, padding.names[0]),
            #[cfg(feature = "sm2")]
            Kind::Message { algorithm, mode } => format!("{}/{}", algorithm.names[0], mode.name),
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
                check(mode.iv(), op.iv.is_some())?;
                check(mode.tag_len(), op.tag_len.is_some())?;
                check(mode.aad(), op.aad.is_some())?;
                symmetric(params)
            }
            // A secret key, the IV if the cipher has one, and nothing else
            Kind::Stream { algorithm } => {
                check(algorithm.iv, op.iv.is_some())?;
                check(Need::Forbidden, op.tag_len.is_some())?;
                check(Need::Forbidden, op.aad.is_some())?;
                symmetric(params)
            }
            // A key of the algorithm, and no operation field at all
            #[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
            Kind::Asymmetric { algorithm, .. } => {
                check(Need::Forbidden, op.iv.is_some())?;
                check(Need::Forbidden, op.tag_len.is_some())?;
                check(Need::Forbidden, op.aad.is_some())?;
                (algorithm.key)(&params.key).ok_or(AlgoError::new(ErrorKind::InvalidParams))
            }
            #[cfg(feature = "sm2")]
            Kind::Message { algorithm, .. } => {
                check(Need::Forbidden, op.iv.is_some())?;
                check(Need::Forbidden, op.tag_len.is_some())?;
                check(Need::Forbidden, op.aad.is_some())?;
                (algorithm.key)(&params.key).ok_or(AlgoError::new(ErrorKind::InvalidParams))
            }
        }
    }
}

fn symmetric(params: &AnyParams) -> Result<InitParams, AlgoError> {
    let AnyKeyParams::Secret(secret) = &params.key else {
        return Err(AlgoError::new(ErrorKind::InvalidParams));
    };
    let op = &params.op;
    Ok(InitParams::Symmetric(SymmetricParams {
        key: Zeroizing::new(secret.key.clone()),
        iv: op.iv.clone(),
        tag_len: op.tag_len,
        aad: op.aad.clone().unwrap_or_default(),
    }))
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
