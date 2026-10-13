//! The parameters of RSA blinding for a blind signature.

use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

use crate::RsaKey;

/// The parameters of [`RsaBlindingEngine`](crate::RsaBlindingEngine), as
/// Bouncy Castle's `RsaBlindingParameters`: the public key of the signer
/// and the blinding factor `r` the requester keeps to itself. It is a
/// container only: nothing is checked when it is built, and the engine
/// turns down a private key, or a factor below 2 or without an inverse
/// modulo `n`, when it is initialized. The factor is wiped on drop; there
/// is no `Debug`, which would show it.
#[derive(Clone)]
pub struct RsaBlindingParams {
    public_key: RsaKey,
    blinding_factor: PaddedBigUint,
}

impl RsaBlindingParams {
    /// The parameters of `public_key` and `blinding_factor`, such as
    /// [`RsaBlindingFactorGenerator`](crate::RsaBlindingFactorGenerator)
    /// draws. Constant time.
    pub const fn new(public_key: RsaKey, blinding_factor: PaddedBigUint) -> Self {
        Self {
            public_key,
            blinding_factor,
        }
    }

    /// The public key of the signer. Constant time.
    pub fn public_key(&self) -> &RsaKey {
        &self.public_key
    }

    /// The blinding factor. Constant time.
    pub fn blinding_factor(&self) -> &PaddedBigUint {
        &self.blinding_factor
    }
}

/// Wipes the blinding factor; the key wipes itself. Constant time.
impl Drop for RsaBlindingParams {
    fn drop(&mut self) {
        self.blinding_factor.zeroize();
    }
}
