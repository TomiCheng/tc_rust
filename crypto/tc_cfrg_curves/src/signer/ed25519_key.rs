use crate::rfc8032::ed25519::{self, ExpandedKey};
use crate::{CfrgError, Ed25519PublicKey};

// 簽章用展開後的私鑰，驗章用公鑰。
pub(super) enum Ed25519Key {
    Signing(ExpandedKey),
    Verifying(Ed25519PublicKey),
}

impl Ed25519Key {
    pub(super) fn signing(key: &Option<Self>) -> Result<&ExpandedKey, CfrgError> {
        match key {
            Some(Self::Signing(key)) => Ok(key),
            Some(Self::Verifying(_)) => Err(CfrgError::NotForSigning),
            None => Err(CfrgError::NotInitialized),
        }
    }

    pub(super) fn verifying(key: &Option<Self>) -> Result<&Ed25519PublicKey, CfrgError> {
        match key {
            Some(Self::Verifying(key)) => Ok(key),
            Some(Self::Signing(_)) => Err(CfrgError::NotForVerifying),
            None => Err(CfrgError::NotInitialized),
        }
    }

    pub(super) fn for_verifying(public_key: &Ed25519PublicKey) -> Result<Self, CfrgError> {
        if ed25519::validate_public_key_partial(public_key.a()) {
            Ok(Self::Verifying(public_key.clone()))
        } else {
            Err(CfrgError::InvalidPublicKey)
        }
    }
}
