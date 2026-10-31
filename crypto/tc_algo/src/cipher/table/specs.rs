use tc_asn1::NamedOid;

use crate::cipher::engine::AnyEngine;

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
