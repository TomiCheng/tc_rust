use std::io;

use tc_algo::{
    Params,
    params::key::{Ed25519PublicKey, X25519PublicKey},
};

pub(super) fn encode_ed25519(key: &dyn Params) -> io::Result<Vec<u8>> {
    key.as_any()
        .downcast_ref::<Ed25519PublicKey>()
        .map(|key| key.a().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected Ed25519 public key material",
            )
        })
}

pub(super) fn encode_x25519(key: &dyn Params) -> io::Result<Vec<u8>> {
    key.as_any()
        .downcast_ref::<X25519PublicKey>()
        .map(|key| key.u().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected X25519 public key material",
            )
        })
}

pub(super) fn decode_ed25519(bytes: &[u8]) -> io::Result<Box<dyn Params>> {
    Ok(Box::new(Ed25519PublicKey::new(key_bytes(bytes)?)))
}

pub(super) fn decode_x25519(bytes: &[u8]) -> io::Result<Box<dyn Params>> {
    Ok(Box::new(X25519PublicKey::new(key_bytes(bytes)?)))
}

fn key_bytes(bytes: &[u8]) -> io::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "expected 32 bytes of public key material",
        )
    })
}
