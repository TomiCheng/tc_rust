use tc_asn1::NamedOid;

use crate::cipher::dyn_cipher::DynCipher;
use crate::cipher::engine::AnyEngine;
#[cfg(any(
    feature = "rsa",
    feature = "elgamal",
    feature = "naccache-stern",
    feature = "sm2"
))]
use crate::cipher::init_params::InitParams;
#[cfg(any(
    feature = "rsa",
    feature = "elgamal",
    feature = "naccache-stern",
    feature = "sm2"
))]
use crate::params::AnyKeyParams;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cipher) enum ModeKind {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
    Ccm,
    Eax,
    Gcm,
    Ocb,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cipher) enum PaddingKind {
    NoPadding,
    Pkcs7,
    Iso10126,
    Iso7816,
    X923,
    Tbc,
    ZeroByte,
}

// Whether a mode needs an operation field: init refuses a required one that is missing and a
// forbidden one that is there, so nothing is filled in silently or dropped silently
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cipher) enum Need {
    Forbidden,
    Optional,
    Required,
}

// One block cipher: its engine, its block size, and the combinations Bouncy Castle gives OIDs
pub(in crate::cipher) struct AlgorithmSpec {
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
    pub(in crate::cipher) block_size: usize,
    pub(in crate::cipher) engine: fn() -> AnyEngine,
    pub(in crate::cipher) oids: &'static [(ModeKind, PaddingKind, &'static [NamedOid])],
}

// One mode: the algorithms it can run on and the padding it takes when none is named
pub(in crate::cipher) struct ModeSpec {
    pub(in crate::cipher) kind: ModeKind,
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
    // AEAD modes take only NoPadding
    pub(in crate::cipher) aead: bool,
    // The block sizes it takes; empty means any
    pub(in crate::cipher) block_sizes: &'static [usize],
    // It handles a partial last block (CFB, OFB, CTR), so no padding is its default
    pub(in crate::cipher) partial_block: bool,
}

impl ModeSpec {
    pub(in crate::cipher) fn supports(&self, algorithm: &AlgorithmSpec) -> bool {
        self.block_sizes.is_empty() || self.block_sizes.contains(&algorithm.block_size)
    }

    // As in Bouncy Castle: no padding for AEAD modes and the modes that take a partial block,
    // PKCS7 for the others
    pub(in crate::cipher) fn default_padding(&self) -> PaddingKind {
        if self.aead || self.partial_block {
            PaddingKind::NoPadding
        } else {
            PaddingKind::Pkcs7
        }
    }

    // Every mode but ECB needs an IV, the nonce in an AEAD mode. Unlike Bouncy Castle, CBC
    // without one is refused rather than run with a zero IV
    pub(in crate::cipher) fn iv(&self) -> Need {
        match self.kind {
            ModeKind::Ecb => Need::Forbidden,
            _ => Need::Required,
        }
    }

    pub(in crate::cipher) fn tag_len(&self) -> Need {
        if self.aead {
            Need::Required
        } else {
            Need::Forbidden
        }
    }

    pub(in crate::cipher) fn aad(&self) -> Need {
        if self.aead {
            Need::Optional
        } else {
            Need::Forbidden
        }
    }
}

pub(in crate::cipher) struct PaddingSpec {
    pub(in crate::cipher) kind: PaddingKind,
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
}

// One stream cipher: it takes a secret key, an IV if it has one, and neither a mode nor a padding
pub(in crate::cipher) struct StreamSpec {
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
    // Required for all but RC4, which has no IV
    pub(in crate::cipher) iv: Need,
    pub(in crate::cipher) create: fn() -> Box<dyn DynCipher>,
    pub(in crate::cipher) oids: &'static [NamedOid],
}

// An asymmetric cipher that encrypts a whole message of any length, not one block, as SM2 does.
// Its modes are its own, and it takes no padding
#[cfg(feature = "sm2")]
pub(in crate::cipher) struct MessageSpec {
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
    // The first is what a name without a mode gives
    pub(in crate::cipher) modes: &'static [MessageModeSpec],
    // The key of the params, if it is one this cipher takes
    pub(in crate::cipher) key: fn(&AnyKeyParams) -> Option<InitParams>,
}

#[cfg(feature = "sm2")]
pub(in crate::cipher) struct MessageModeSpec {
    pub(in crate::cipher) name: &'static str,
    pub(in crate::cipher) create: fn() -> Box<dyn DynCipher>,
}

// One asymmetric cipher: it takes the paddings it lists, and no mode
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
pub(in crate::cipher) struct AsymmetricSpec {
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
    pub(in crate::cipher) paddings: &'static [AsymmetricPaddingKind],
    // Called only with one of its paddings
    pub(in crate::cipher) create: fn(AsymmetricPaddingKind) -> Box<dyn DynCipher>,
    // The key of the params, if it is one of this algorithm's
    pub(in crate::cipher) key: fn(&AnyKeyParams) -> Option<InitParams>,
    pub(in crate::cipher) oids: &'static [(AsymmetricPaddingKind, &'static [NamedOid])],
}

// The OAEP variants are those of Bouncy Castle: the hash of the label first, then that of MGF1
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cipher) enum AsymmetricPaddingKind {
    NoPadding,
    Pkcs1,
    #[cfg(feature = "rsa-iso9796")]
    Iso9796d1,
    #[cfg(feature = "md5")]
    OaepMd5,
    OaepSha1,
    OaepSha224,
    OaepSha256,
    OaepSha256Mgf1Sha1,
    OaepSha384,
    OaepSha512,
}

#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
pub(in crate::cipher) struct AsymmetricPaddingSpec {
    pub(in crate::cipher) kind: AsymmetricPaddingKind,
    // The first is the canonical name, the rest are aliases
    pub(in crate::cipher) names: &'static [&'static str],
}
