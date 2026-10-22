use crate::{Ed25519PrivateKey, Ed25519PublicKey};

pub(super) enum Ed25519Key {
    Signing(Ed25519PrivateKey),
    Verifying(Ed25519PublicKey),
}
