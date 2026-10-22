use crate::{Ed448PrivateKey, Ed448PublicKey};

pub(super) enum Ed448Key {
    Signing(Ed448PrivateKey),
    Verifying(Ed448PublicKey),
}
