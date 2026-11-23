use std::io::{self, Read};

use tc_algo::{
    Algo,
    params::key::{RsaKey, RsaKeyParams},
};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_openpgp_packet::{
    HashAlgorithmTag, PublicKeyAlgorithmTag, PublicKeyVersion, SignaturePacket,
};

use super::{document_is_text, read_document};
use crate::{
    PgpPublicKey,
    operator::{rsa_mpi::read_mpi, serializer::v4_fingerprint, signature_subpacket::Subpackets},
};

pub(super) fn verify(
    algo: &dyn Algo,
    key: &PgpPublicKey,
    document: &mut dyn Read,
    packet: &SignaturePacket,
) -> io::Result<bool> {
    let text = document_is_text(packet)?;
    if key.version() != PublicKeyVersion::V4
        || !can_sign(key.algorithm())
        || !can_sign(packet.public_key_algorithm())
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "expected a v4 RSA signing key and signature",
        ));
    }
    let rsa = key
        .key()
        .as_any()
        .downcast_ref::<RsaKey>()
        .filter(|key| !key.is_private_key())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected RSA public key material",
            )
        })?;

    let (hash_name, signer_name) = match packet.hash_algorithm() {
        HashAlgorithmTag::Sha224 => ("SHA-224", "SHA-224withRSA"),
        HashAlgorithmTag::Sha256 => ("SHA-256", "SHA-256withRSA"),
        HashAlgorithmTag::Sha384 => ("SHA-384", "SHA-384withRSA"),
        HashAlgorithmTag::Sha512 => ("SHA-512", "SHA-512withRSA"),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported v4 RSA signature hash",
            ));
        }
    };
    let mut material = packet.signature();
    let signature = read_mpi(&mut material)?;
    if signature.is_empty() || !material.is_empty() {
        return Err(invalid("expected exactly one nonzero RSA signature MPI"));
    }
    let modulus_len = rsa.modulus().bits().div_ceil(8) as usize;
    let Some(offset) = modulus_len.checked_sub(signature.len()) else {
        return Ok(false);
    };
    let mut padded = vec![0; modulus_len];
    padded[offset..].copy_from_slice(signature);

    if !verify_hashed_subpackets(algo, key, packet)? {
        return Ok(false);
    }

    let mut verifier = algo
        .signer()
        .get_by_name(signer_name)
        .map_err(io::Error::other)?;
    verifier.init(rsa).map_err(io::Error::other)?;
    let mut digest = algo
        .digest()
        .get_by_name(hash_name)
        .map_err(io::Error::other)?;
    let mut update = |chunk: &[u8]| -> io::Result<()> {
        verifier.update(chunk).map_err(io::Error::other)?;
        digest.try_update(chunk).map_err(io::Error::other)
    };
    read_document(document, text, &mut update)?;
    let mut suffix = Vec::new();
    packet.write_hash_suffix(&mut suffix)?;
    update(&suffix)?;

    let hash = digest.finalize().map_err(io::Error::other)?;
    let Some(prefix) = hash.get(..2) else {
        return Err(io::Error::other("invalid signature digest length"));
    };
    if prefix != packet.hash_prefix() {
        return Ok(false);
    }
    verifier.verify_signature(&padded).map_err(io::Error::other)
}

fn verify_hashed_subpackets(
    algo: &dyn Algo,
    key: &PgpPublicKey,
    packet: &SignaturePacket,
) -> io::Result<bool> {
    let mut issuer = None;
    let mut key_id = None;
    let mut creation_seen = false;
    for item in Subpackets::new(packet.hashed_subpackets()) {
        let (tag, value) = item?;
        match tag & 0x7f {
            2 if !creation_seen && value.len() == 4 => creation_seen = true,
            16 if key_id.is_none() && value.len() == 8 => key_id = Some(value),
            33 if issuer.is_none() && value.len() == 21 && value[0] == 4 => {
                issuer = Some(&value[1..])
            }
            2 | 16 | 33 => {
                return Err(invalid(
                    "malformed or duplicate v4 signature identification",
                ));
            }
            _ if tag & 0x80 != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported critical signature subpacket",
                ));
            }
            _ => {}
        }
    }
    if !creation_seen {
        return Err(invalid("missing hashed signature creation time"));
    }
    if issuer.is_none() && key_id.is_none() {
        return Ok(true);
    }

    // SHA-1 is only used for the v4 key fingerprint, never for RSA verification.
    let fingerprint = v4_fingerprint(algo, key)?;
    Ok(issuer.is_none_or(|expected| expected == fingerprint)
        && key_id.is_none_or(|expected| expected == &fingerprint[12..]))
}

fn can_sign(algorithm: PublicKeyAlgorithmTag) -> bool {
    matches!(
        algorithm,
        PublicKeyAlgorithmTag::RsaGeneral | PublicKeyAlgorithmTag::RsaSign
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
