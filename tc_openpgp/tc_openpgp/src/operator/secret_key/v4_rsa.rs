use std::io::{self, Read};

use tc_algo::{
    Algo,
    params::{
        cipher::KeyWithIvOwned,
        key::{RsaKey, RsaKeyParams},
    },
};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_constant_time::fixed_time_eq;
use tc_openpgp_packet::{
    BodyLength, DecodingConfig, PacketTag, PgpReader, PublicKeyAlgorithmTag, PublicKeyPacket,
    PublicKeyVersion,
};
use tc_rsa::RsaPrivateCrtKeyOwned;
use tc_zeroize::Zeroizing;

use super::{PgpRsaSecretKeys, SecretKeyLimits};
use crate::{
    PgpKeyPair, PgpPrivateKey, PgpPublicKey,
    operator::{rsa_mpi::read_mpi, serializer::decode_key_packet},
};

const MAX_RSA_BYTES: usize = 2048;
const MAX_KEY_BODY_LEN: usize = 6 + 6 * (MAX_RSA_BYTES + 2) + 29 + 20;

pub(super) fn import(
    algo: &dyn Algo,
    mut input: &[u8],
    passphrase: &[u8],
    config: &DecodingConfig,
    limits: &SecretKeyLimits,
) -> io::Result<PgpRsaSecretKeys> {
    let mut primary = None;
    let mut subkeys = Vec::new();
    while !input.is_empty() {
        let mut reader = PgpReader::new(&mut input);
        let (header, mut body) = reader.read_body(config)?;
        let BodyLength::Fixed(len) = header.body_length() else {
            return Err(invalid("expected a definite-length v4 secret-key bundle"));
        };
        match header.tag() {
            PacketTag::SecretKey | PacketTag::SecretSubkey
                if primary.is_none() == (header.tag() == PacketTag::SecretKey) =>
            {
                if usize::from(primary.is_some()) + subkeys.len() >= limits.max_keys
                    || len as usize > MAX_KEY_BODY_LEN
                {
                    return Err(invalid("v4 secret-key bundle exceeds its limits"));
                }
                let mut bytes = Zeroizing::new(Vec::new());
                body.read_to_end(&mut bytes)?;
                let key = unlock(algo, &bytes, passphrase)?;
                if primary.is_none() {
                    primary = Some(key);
                } else {
                    subkeys.push(key);
                }
            }
            PacketTag::Signature if primary.is_some() => {
                io::copy(&mut body, &mut io::sink())?;
            }
            PacketTag::UserId | PacketTag::UserAttribute
                if primary.is_some() && subkeys.is_empty() =>
            {
                io::copy(&mut body, &mut io::sink())?;
            }
            _ => return Err(invalid("unexpected packet in v4 RSA secret-key bundle")),
        }
    }
    let primary = primary.ok_or_else(|| invalid("missing v4 RSA primary secret key"))?;
    Ok(PgpRsaSecretKeys { primary, subkeys })
}

fn unlock(algo: &dyn Algo, body: &[u8], passphrase: &[u8]) -> io::Result<PgpKeyPair> {
    let Some(([4, a, b, c, d, id], mut rest)) = body.split_first_chunk::<6>() else {
        return Err(unsupported("expected a v4 RSA secret-key packet"));
    };
    let tag = PublicKeyAlgorithmTag::from(*id);
    if !matches!(
        tag,
        PublicKeyAlgorithmTag::RsaGeneral
            | PublicKeyAlgorithmTag::RsaEncrypt
            | PublicKeyAlgorithmTag::RsaSign
    ) {
        return Err(unsupported("expected RSA secret key material"));
    }
    let start = rest;
    let modulus = read_mpi(&mut rest)?;
    read_mpi(&mut rest)?;
    if modulus.is_empty() || modulus.len() > MAX_RSA_BYTES {
        return Err(invalid("unsupported RSA modulus length"));
    }
    let material = start[..start.len() - rest.len()].to_vec();
    let packet = PublicKeyPacket::new(
        PublicKeyVersion::V4,
        u32::from_be_bytes([*a, *b, *c, *d]),
        tag,
        material,
    );
    let public = decode_key_packet(&packet)?;

    let Some(([254, cipher, 3, hash, salt @ .., count], rest)) = rest.split_first_chunk::<13>()
    else {
        return Err(unsupported(
            "expected CFB-protected secret key with iterated-and-salted S2K",
        ));
    };
    let key_len = match cipher {
        7 => 16,
        8 => 24,
        9 => 32,
        _ => return Err(unsupported("expected AES secret-key protection")),
    };
    let (hash_name, hash_len) = match hash {
        2 => ("SHA-1", 20),
        8 => ("SHA-256", 32),
        9 => ("SHA-384", 48),
        10 => ("SHA-512", 64),
        11 => ("SHA-224", 28),
        _ => return Err(unsupported("unsupported v4 RSA S2K digest")),
    };
    let Some((iv, encrypted)) = rest.split_first_chunk::<16>() else {
        return Err(rejected());
    };
    if encrypted.len() < 20 {
        return Err(rejected());
    }
    let mut key = derive_s2k(
        algo,
        (hash_name, hash_len),
        salt,
        passphrase,
        *count,
        key_len,
    )?;
    let params = KeyWithIvOwned::new(std::mem::take(&mut *key), iv.to_vec());
    let plaintext = Zeroizing::new(
        algo.cipher()
            .decrypt_by_name("AES/CFB/NOPADDING", &params, encrypted)
            .map_err(|_| rejected())?,
    );
    let hash_start = plaintext.len().checked_sub(20).ok_or_else(rejected)?;
    let (material, checksum) = plaintext.split_at(hash_start);
    let actual = algo
        .digest()
        .calculate_by_name("SHA-1", material)
        .map_err(io::Error::other)?;
    if !fixed_time_eq(&actual, checksum) {
        return Err(rejected());
    }
    let private = decode_private(&public, modulus.len(), material)?;
    Ok(PgpKeyPair::new(
        public,
        PgpPrivateKey::new(tag, Box::new(private)),
    ))
}

fn derive_s2k(
    algo: &dyn Algo,
    (hash_name, hash_len): (&str, usize),
    salt: &[u8; 8],
    passphrase: &[u8],
    encoded_count: u8,
    key_len: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let cycle_len = salt
        .len()
        .checked_add(passphrase.len())
        .ok_or_else(rejected)?;
    let repetitions = (4096 / cycle_len).max(1);
    let mut pattern = Zeroizing::new(Vec::with_capacity(cycle_len * repetitions));
    for _ in 0..repetitions {
        pattern.extend_from_slice(salt);
        pattern.extend_from_slice(passphrase);
    }
    let count = (16 + usize::from(encoded_count & 15)) << (6 + (encoded_count >> 4));
    let count = count.max(cycle_len);
    let mut key = Zeroizing::new(Vec::with_capacity(key_len));
    for round in 0..key_len.div_ceil(hash_len) {
        let mut digest = algo
            .digest()
            .get_by_name(hash_name)
            .map_err(io::Error::other)?;
        for _ in 0..round {
            digest.try_update(&[0]).map_err(io::Error::other)?;
        }
        let mut remaining = count;
        while remaining != 0 {
            let len = remaining.min(pattern.len());
            digest
                .try_update(&pattern[..len])
                .map_err(io::Error::other)?;
            remaining -= len;
        }
        let part = Zeroizing::new(digest.finalize().map_err(io::Error::other)?);
        if part.len() != hash_len {
            return Err(io::Error::other("unexpected S2K digest length"));
        }
        let len = (key_len - key.len()).min(part.len());
        key.extend_from_slice(&part[..len]);
    }
    Ok(key)
}

fn decode_private(public: &PgpPublicKey, width: usize, mut input: &[u8]) -> io::Result<RsaKey> {
    let public = public
        .key()
        .as_any()
        .downcast_ref::<RsaKey>()
        .ok_or_else(rejected)?;
    let d = secret_mpi(&mut input, width)?;
    let p = secret_mpi(&mut input, width)?;
    let q = secret_mpi(&mut input, width)?;
    let u = secret_mpi(&mut input, width)?;
    if !input.is_empty()
        || [p, q]
            .iter()
            .any(|prime| *prime == [1] || prime.last().unwrap() & 1 == 0)
    {
        return Err(rejected());
    }

    let half = width.div_ceil(2).max(p.len()).max(q.len());
    let half_p = Zeroizing::new(padded(p, half));
    let half_q = Zeroizing::new(padded(q, half));
    let coefficient = Zeroizing::new(padded(u, half));
    let d = Zeroizing::new(padded(d, width));
    let one = PaddedBigUint::from(1u8);
    if *half_p == *half_q || *coefficient >= *half_q || *d <= one || &*d >= public.modulus() {
        return Err(rejected());
    }

    // Two modulus widths prevent overflow even when the input factors are invalid.
    let wide_p = Zeroizing::new(padded(p, 2 * width));
    let product = Zeroizing::new(&*wide_p * &*half_q);
    let pu = Zeroizing::new(&*wide_p * &*coefficient);
    let inverse_check = Zeroizing::new(&*pu % &*half_q);
    if &*product != public.modulus() || *inverse_check != one {
        return Err(rejected());
    }
    let p_minus_one = Zeroizing::new(&*half_p - 1u32);
    let q_minus_one = Zeroizing::new(&*half_q - 1u32);
    let e_bytes = ArrayEncoding::<u8>::to_be(public.exponent());
    let wide_e = padded(&e_bytes, 2 * width);
    let ed = Zeroizing::new(&wide_e * &*d);
    let p_check = Zeroizing::new(&*ed % &*p_minus_one);
    let q_check = Zeroizing::new(&*ed % &*q_minus_one);
    if *p_check != one || *q_check != one {
        return Err(rejected());
    }
    let dp = Zeroizing::new(&*d % &*p_minus_one);
    let dq = Zeroizing::new(&*d % &*q_minus_one);
    let dp_bytes = Zeroizing::new(ArrayEncoding::<u8>::to_be(&*dp));
    let dq_bytes = Zeroizing::new(ArrayEncoding::<u8>::to_be(&*dq));

    // OpenPGP uses u = p^-1 mod q. Swapping the primes makes u the CRT
    // coefficient the local RSA engine expects, without another inversion.
    let crt = RsaPrivateCrtKeyOwned::new(
        public.modulus().clone(),
        public.exponent().clone(),
        (*d).clone(),
        (*half_q).clone(),
        (*half_p).clone(),
        padded(&dq_bytes[dq_bytes.len() - half..], half),
        padded(&dp_bytes[dp_bytes.len() - half..], half),
        (*coefficient).clone(),
    );
    if !crt.validate() {
        return Err(rejected());
    }
    Ok(RsaKey::Crt(crt))
}

fn secret_mpi<'a>(input: &mut &'a [u8], width: usize) -> io::Result<&'a [u8]> {
    let bytes = read_mpi(input).map_err(|_| rejected())?;
    if bytes.is_empty() || bytes.len() > width {
        return Err(rejected());
    }
    Ok(bytes)
}

fn padded(bytes: &[u8], width: usize) -> PaddedBigUint {
    let mut buffer = Zeroizing::new(vec![0; width.max(bytes.len())]);
    let offset = buffer.len() - bytes.len();
    buffer[offset..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    value
}

fn rejected() -> io::Error {
    invalid("v4 RSA secret key integrity check failed")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

    #[test]
    fn sha1_s2k_extends_an_aes256_key_with_a_second_digest_context() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = derive_s2k(&*algo, ("SHA-1", 20), b"12345678", b"sample", 0, 32).unwrap();
        assert_eq!(
            &key[..],
            &[
                0xba, 0x51, 0x77, 0xbe, 0xc9, 0x66, 0x26, 0x4a, 0x8d, 0x2b, 0xed, 0xcc, 0x8a, 0x72,
                0x13, 0x3e, 0x42, 0x2e, 0xd4, 0xf7, 0x07, 0x35, 0xd2, 0x1a, 0x8b, 0xb6, 0xda, 0xb8,
                0xb9, 0x8f, 0x34, 0x0e,
            ]
        );
    }
}
