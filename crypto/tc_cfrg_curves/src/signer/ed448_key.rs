use crate::rfc8032::ed448::{self, ExpandedKey};
use crate::{CfrgError, Ed448PublicKey};

// 簽章用展開後的私鑰，驗章用公鑰。
pub(super) enum Ed448Key {
    Signing(ExpandedKey),
    Verifying(Ed448PublicKey),
}

impl Ed448Key {
    pub(super) fn signing(key: &Option<Self>) -> Result<&ExpandedKey, CfrgError> {
        match key {
            Some(Self::Signing(key)) => Ok(key),
            Some(Self::Verifying(_)) => Err(CfrgError::NotForSigning),
            None => Err(CfrgError::NotInitialized),
        }
    }

    pub(super) fn verifying(key: &Option<Self>) -> Result<&Ed448PublicKey, CfrgError> {
        match key {
            Some(Self::Verifying(key)) => Ok(key),
            Some(Self::Signing(_)) => Err(CfrgError::NotForVerifying),
            None => Err(CfrgError::NotInitialized),
        }
    }

    pub(super) fn for_verifying(public_key: &Ed448PublicKey) -> Result<Self, CfrgError> {
        if ed448::validate_public_key_partial(public_key.a()) {
            Ok(Self::Verifying(public_key.clone()))
        } else {
            Err(CfrgError::InvalidPublicKey)
        }
    }
}
