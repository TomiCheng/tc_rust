use std::io::{self, Read};

use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use tc_algo::{
    Algo,
    params::{
        cipher::KeyWithIvOwned,
        key::{RsaKey, RsaKeyParams},
    },
};
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_asym_encoding::Pkcs1Encoding;
use tc_constant_time::fixed_time_eq;
use tc_openpgp_packet::{
    BodyLength, DecodingConfig, LiteralData, PacketTag, PgpRead, PgpReader, PublicKeyAlgorithmTag,
    PublicKeyVersion,
};
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaPrivateCrtKeyParams};
use tc_zeroize::Zeroizing;

use crate::{
    PgpKeyPair,
    operator::{rsa_mpi::read_mpi, serializer::v4_fingerprint},
};

const CFB_PREFIX_LEN: usize = 18;
const MDC_HEADER: [u8; 2] = [0xd3, 0x14];
const MDC_HASH_LEN: usize = 20;

pub(super) fn decrypt(
    algo: &dyn Algo,
    recipient: &PgpKeyPair,
    input: &mut dyn Read,
    config: &DecodingConfig,
) -> io::Result<LiteralData> {
    let private = matching_private(recipient)?;
    let fingerprint = v4_fingerprint(algo, recipient.public())?;
    let mut reader = PgpReader::new(input);
    let mut encrypted_session = None;
    let modulus_len = private.modulus().bits().div_ceil(8) as usize;
    let mut body = loop {
        let (header, mut body) = reader.read_body(config)?;
        match (header.tag(), header.body_length()) {
            (
                PacketTag::SymmetricEncryptedIntegrityProtected,
                BodyLength::Fixed(_) | BodyLength::Partial(_),
            ) => break body,
            (PacketTag::PublicKeyEncryptedSession, BodyLength::Fixed(_)) => {}
            _ => return Err(invalid("expected v3 PKESK or v1 SEIPD packet")),
        }

        let mut prefix = [0; 10];
        body.read_exact(&mut prefix)?;
        if prefix[0] != 3 {
            return Err(unsupported("expected a v3 encrypted session key"));
        }
        let algorithm = PublicKeyAlgorithmTag::from(prefix[9]);
        if encrypted_session.is_none()
            && can_encrypt(algorithm)
            && prefix[1..9] == fingerprint[12..]
        {
            let mut mpi = Vec::new();
            let limit = (modulus_len + 3) as u64;
            (&mut body).take(limit).read_to_end(&mut mpi)?;
            let mut encoded = mpi.as_slice();
            let value = read_mpi(&mut encoded).map_err(|_| rejected())?;
            if value.is_empty() || !encoded.is_empty() || value.len() > modulus_len {
                return Err(rejected());
            }
            let mut padded = vec![0; modulus_len];
            padded[modulus_len - value.len()..].copy_from_slice(value);
            encrypted_session = Some(padded);
        } else {
            io::copy(&mut body, &mut io::sink())?;
        }
    };
    let encrypted_session = encrypted_session.ok_or_else(rejected)?;
    let mut version = [0];
    body.read_exact(&mut version)?;
    if version != [1] {
        return Err(unsupported("expected a v1 integrity-protected data packet"));
    }
    let mut ciphertext = Vec::new();
    body.read_to_end(&mut ciphertext)?;
    if ciphertext.len() < CFB_PREFIX_LEN + MDC_HEADER.len() + MDC_HASH_LEN {
        return Err(rejected());
    }

    let plaintext = open_message(algo, private, &encrypted_session, &ciphertext)?;
    let data_end = plaintext.len() - MDC_HEADER.len() - MDC_HASH_LEN;
    let config = DecodingConfig {
        header_format: None,
        ..*config
    };
    let mut packets = &plaintext[CFB_PREFIX_LEN..data_end];
    let literal = LiteralData::decode(&mut packets, &config)?;
    if !packets.is_empty() {
        return Err(invalid("trailing packets after OpenPGP literal data"));
    }
    Ok(literal)
}

fn open_message(
    algo: &dyn Algo,
    private: &RsaKey,
    encrypted_session: &[u8],
    ciphertext: &[u8],
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(io::Error::other)?;
    let mut verified = None;
    // Each supported session-key width uses implicit PKCS#1 rejection. Always
    // run CFB and MDC for all widths before deciding whether to return plaintext.
    for (cipher, key_len) in [(7, 16), (8, 24), (9, 32)] {
        let engine = RsaBlindedEngine::from_parts(RsaEngine::new(), &mut rng);
        let mut pkcs1 = Pkcs1Encoding::from_parts(
            engine,
            StdRng::try_from_rng(&mut SysRng).map_err(io::Error::other)?,
        )
        .with_plaintext_length(key_len + 3);
        pkcs1
            .init(CipherDirection::Decrypt, private)
            .map_err(|_| rejected())?;
        let mut session = Zeroizing::new(vec![0; pkcs1.output_block_size()]);
        if pkcs1
            .process_block(encrypted_session, &mut session)
            .map_err(|_| rejected())?
            != key_len + 3
        {
            return Err(rejected());
        }

        let key = &session[1..key_len + 1];
        let checksum = key
            .iter()
            .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
        let session_valid = fixed_time_eq(&session[..1], &[cipher])
            & fixed_time_eq(&session[key_len + 1..key_len + 3], &checksum.to_be_bytes());
        let params = KeyWithIvOwned::new(key.to_vec(), vec![0; 16]);
        let plaintext = Zeroizing::new(
            algo.cipher()
                .decrypt_by_name("AES/CFB/NOPADDING", &params, ciphertext)
                .map_err(|_| rejected())?,
        );
        if plaintext.len() != ciphertext.len() {
            return Err(rejected());
        }
        let valid = verify_mdc(algo, &plaintext)? & session_valid;
        if valid {
            verified = Some(plaintext);
        }
    }
    verified.ok_or_else(rejected)
}

fn verify_mdc(algo: &dyn Algo, plaintext: &[u8]) -> io::Result<bool> {
    let hash_start = plaintext.len() - MDC_HASH_LEN;
    let expected = algo
        .digest()
        .calculate_by_name("SHA-1", &plaintext[..hash_start])
        .map_err(|_| rejected())?;
    let prefix_ok = fixed_time_eq(&plaintext[14..16], &plaintext[16..18]);
    let mdc_header_ok = fixed_time_eq(
        &plaintext[hash_start - MDC_HEADER.len()..hash_start],
        &MDC_HEADER,
    );
    Ok(prefix_ok & mdc_header_ok & fixed_time_eq(&expected, &plaintext[hash_start..]))
}

fn matching_private(recipient: &PgpKeyPair) -> io::Result<&RsaKey> {
    let public = recipient.public();
    let private = recipient.private();
    if public.version() != PublicKeyVersion::V4
        || !can_encrypt(public.algorithm())
        || !can_encrypt(private.algorithm())
    {
        return Err(unsupported("expected a v4 RSA encryption key pair"));
    }
    let public = public
        .key()
        .as_any()
        .downcast_ref::<RsaKey>()
        .filter(|key| !key.is_private_key());
    let private = private.key().as_any().downcast_ref::<RsaKey>();
    match (public, private) {
        (Some(public), Some(private @ RsaKey::Crt(crt)))
            if public.modulus() == crt.modulus() && public.exponent() == crt.public_exponent() =>
        {
            Ok(private)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected matching RSA public and CRT private keys",
        )),
    }
}

fn can_encrypt(algorithm: PublicKeyAlgorithmTag) -> bool {
    matches!(
        algorithm,
        PublicKeyAlgorithmTag::RsaGeneral | PublicKeyAlgorithmTag::RsaEncrypt
    )
}

fn rejected() -> io::Error {
    invalid("OpenPGP RSA message integrity check failed")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
