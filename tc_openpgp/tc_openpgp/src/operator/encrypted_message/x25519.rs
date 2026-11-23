use std::{
    io::{self, Read, Write},
    sync::Arc,
};

use rand::rngs::SysRng;
use rand_core::TryRng;
use tc_algo::{
    Algo, AlgoError,
    params::{
        cipher::AeadParamsOwned,
        kdf::HkdfParamsOwned,
        key::{KeyOwned, X25519PrivateKey, X25519PublicKey},
    },
};
use tc_openpgp_packet::{
    BodyLength, DecodingConfig, EncodingConfig, LiteralData, PacketTag, PgpRead, PgpReader,
    PgpWrite, PgpWriter, PublicKeyAlgorithmTag, PublicKeyVersion,
};
use tc_zeroize::Zeroizing;

use super::PgpEncryptedMessageProvider;
use crate::{PgpKeyPair, PgpPublicKey, operator::serializer::v6_fingerprint};

const PKESK_LEN: u32 = 93;
const OCB_TAG_LEN: usize = 16;
const CHUNK_SIZE_OCTET: u8 = 6;
const AES128: u8 = 7;
const OCB: u8 = 2;

pub(crate) struct X25519EncryptedMessages {
    pub(crate) algo: Arc<dyn Algo>,
}

impl PgpEncryptedMessageProvider for X25519EncryptedMessages {
    fn encrypt(
        &self,
        recipient: &PgpPublicKey,
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        let public = public_key(recipient)?;
        let fingerprint = v6_fingerprint(&*self.algo, recipient)?;

        let mut entropy = Zeroizing::new([0; 80]);
        SysRng
            .try_fill_bytes(&mut entropy[..])
            .map_err(io::Error::other)?;
        let mut scalar = Zeroizing::new([0; 32]);
        scalar.copy_from_slice(&entropy[..32]);
        let ephemeral_private = X25519PrivateKey::new(*scalar);
        let ephemeral_public = ephemeral_private.generate_public_key();
        let kek = self.wrapping_key(&ephemeral_private, public, &ephemeral_public, public)?;
        let wrapped = self
            .algo
            .wrap()
            .wrap_by_name("AESWRAP", &kek, &entropy[32..48])
            .map_err(crypto)?;
        if wrapped.len() != 24 {
            return Err(io::Error::other(
                "AES key wrap returned an invalid session key size",
            ));
        }

        let salt = &entropy[48..];
        let mut plaintext = Zeroizing::new(Vec::new());
        data.encode(&mut *plaintext, &EncodingConfig::default())?;
        let ocb = OcbMessage::new(&*self.algo, &entropy[32..48], salt, CHUNK_SIZE_OCTET)?;
        let chunk_size = ocb.chunk_size();
        let encrypted_len = (plaintext.len() as u64)
            + (plaintext.len().div_ceil(chunk_size) as u64 + 1) * OCB_TAG_LEN as u64
            + 36;
        let encrypted_len = u32::try_from(encrypted_len)
            .map_err(|_| invalid("encrypted OpenPGP message is too long"))?;

        let mut packets = PgpWriter::new(output);
        let mut pkesk = packets.write_body(
            PacketTag::PublicKeyEncryptedSession,
            BodyLength::Fixed(PKESK_LEN),
        )?;
        pkesk.write_all(&[6, 33, 6])?;
        pkesk.write_all(&fingerprint)?;
        pkesk.write_all(&[25])?;
        pkesk.write_all(ephemeral_public.u())?;
        pkesk.write_all(&[24])?;
        pkesk.write_all(&wrapped)?;
        pkesk.finish()?;

        let mut data = packets.write_body(
            PacketTag::SymmetricEncryptedIntegrityProtected,
            BodyLength::Fixed(encrypted_len),
        )?;
        data.write_all(&ocb.aad[1..])?;
        data.write_all(salt)?;
        for (index, chunk) in plaintext.chunks(chunk_size).enumerate() {
            data.write_all(&ocb.seal(index as u64, None, chunk)?)?;
        }
        let count = plaintext.len().div_ceil(chunk_size) as u64;
        data.write_all(&ocb.seal(count, Some(plaintext.len() as u64), &[])?)?;
        data.finish()
    }

    fn decrypt(
        &self,
        recipient: &PgpKeyPair,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        let public = public_key(recipient.public())?;
        let private = recipient
            .private()
            .key()
            .as_any()
            .downcast_ref::<X25519PrivateKey>()
            .filter(|private| {
                recipient.private().algorithm() == PublicKeyAlgorithmTag::X25519
                    && &private.generate_public_key() == public
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected a matching X25519 key pair",
                )
            })?;
        let mut reader = PgpReader::new(input);
        let session = {
            let (header, mut body) = reader.read_body(config)?;
            if header.tag() != PacketTag::PublicKeyEncryptedSession
                || header.body_length() != BodyLength::Fixed(PKESK_LEN)
            {
                return Err(invalid("expected a v6 X25519 encrypted session key"));
            }
            let fields: [u8; PKESK_LEN as usize] = read_array(&mut body)?;
            if fields[..3] != [6, 33, 6] || fields[35] != 25 || fields[68] != 24 {
                return Err(invalid(
                    "unsupported v6 X25519 encrypted session key fields",
                ));
            }
            if fields[3..35] != v6_fingerprint(&*self.algo, recipient.public())? {
                return Err(invalid("OpenPGP message is for a different recipient"));
            }
            let ephemeral = X25519PublicKey::new(
                fields[36..68]
                    .try_into()
                    .map_err(|_| invalid("invalid ephemeral key"))?,
            );
            let kek = self.wrapping_key(private, &ephemeral, &ephemeral, public)?;
            let session = Zeroizing::new(
                self.algo
                    .wrap()
                    .unwrap_by_name("AESWRAP", &kek, &fields[69..])
                    .map_err(authentication)?,
            );
            if session.len() != 16 {
                return Err(invalid("invalid AES-128 session key length"));
            }
            session
        };

        let (header, mut body) = reader.read_body(config)?;
        if header.tag() != PacketTag::SymmetricEncryptedIntegrityProtected
            || header.body_length() == BodyLength::Indeterminate
        {
            return Err(invalid(
                "expected an OpenPGP integrity-protected data packet",
            ));
        }
        let [version, cipher, mode, chunk_size] = read_array(&mut body)?;
        if [version, cipher, mode] != [2, AES128, OCB] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only v2 AES-128/OCB messages are supported",
            ));
        }
        let salt: [u8; 32] = read_array(&mut body)?;
        let ocb = OcbMessage::new(&*self.algo, &session, &salt, chunk_size)?;
        let mut encrypted = Vec::new();
        body.read_to_end(&mut encrypted)?;
        let plaintext = ocb.open(&encrypted)?;
        let mut packets = plaintext.as_slice();
        let inner_config = DecodingConfig {
            header_format: None,
            ..*config
        };
        let literal = LiteralData::decode(&mut packets, &inner_config)?;
        while !packets.is_empty() {
            let mut trailing = PgpReader::new(&mut packets);
            let (header, mut body) = trailing.read_body(&inner_config)?;
            if header.tag() != PacketTag::Padding
                || !matches!(header.body_length(), BodyLength::Fixed(_))
            {
                return Err(invalid("expected only padding after OpenPGP literal data"));
            }
            io::copy(&mut body, &mut io::sink())?;
        }
        Ok(literal)
    }
}

impl X25519EncryptedMessages {
    fn wrapping_key(
        &self,
        private: &X25519PrivateKey,
        peer: &X25519PublicKey,
        ephemeral: &X25519PublicKey,
        recipient: &X25519PublicKey,
    ) -> io::Result<KeyOwned> {
        let mut agreement = self
            .algo
            .agreement()
            .get_by_name("X25519")
            .map_err(crypto)?;
        agreement.init(private).map_err(crypto)?;
        let mut ikm = Zeroizing::new(vec![0; 96]);
        ikm[..32].copy_from_slice(ephemeral.u());
        ikm[32..64].copy_from_slice(recipient.u());
        agreement
            .calculate_agreement(peer, &mut ikm[64..])
            .map_err(authentication)?;
        if ikm[64..].iter().all(|byte| *byte == 0) {
            return Err(invalid("invalid X25519 shared secret"));
        }
        let key = hkdf(&*self.algo, &ikm, &[], b"OpenPGP X25519", 16)?;
        let mut key = key;
        Ok(KeyOwned::new(std::mem::take(&mut *key)))
    }
}

struct OcbMessage<'a> {
    algo: &'a dyn Algo,
    derived: Zeroizing<Vec<u8>>,
    aad: [u8; 5],
}

impl<'a> OcbMessage<'a> {
    fn new(algo: &'a dyn Algo, session: &[u8], salt: &[u8], chunk_size: u8) -> io::Result<Self> {
        if chunk_size > 16 {
            return Err(invalid("invalid OpenPGP encrypted data chunk size"));
        }
        let aad = [0xd2, 2, AES128, OCB, chunk_size];
        let derived = hkdf(algo, session, salt, &aad, 23)?;
        Ok(Self { algo, derived, aad })
    }

    fn chunk_size(&self) -> usize {
        1 << (self.aad[4] + 6)
    }

    fn params(&self, index: u64, total: Option<u64>) -> AeadParamsOwned {
        let mut nonce = self.derived[16..].to_vec();
        nonce.extend_from_slice(&index.to_be_bytes());
        let mut aad = self.aad.to_vec();
        if let Some(total) = total {
            aad.extend_from_slice(&total.to_be_bytes());
        }
        AeadParamsOwned::new(self.derived[..16].to_vec(), nonce, OCB_TAG_LEN, aad)
    }

    fn seal(&self, index: u64, total: Option<u64>, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let encrypted = self
            .algo
            .cipher()
            .encrypt_by_name("AES/OCB/NoPadding", &self.params(index, total), bytes)
            .map_err(crypto)?;
        if encrypted.len() != bytes.len() + OCB_TAG_LEN {
            return Err(io::Error::other("OCB returned an invalid ciphertext size"));
        }
        Ok(encrypted)
    }

    fn open(&self, bytes: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let final_offset = bytes
            .len()
            .checked_sub(OCB_TAG_LEN)
            .ok_or_else(|| invalid("missing OpenPGP authentication tag"))?;
        let (encrypted, final_tag) = bytes.split_at(final_offset);
        if encrypted.len() <= OCB_TAG_LEN {
            return Err(invalid("missing encrypted OpenPGP message data"));
        }

        let mut plaintext = Zeroizing::new(Vec::new());
        let mut count = 0;
        for chunk in encrypted.chunks(self.chunk_size() + OCB_TAG_LEN) {
            if chunk.len() <= OCB_TAG_LEN {
                return Err(invalid("truncated OpenPGP encrypted chunk"));
            }
            let decoded = Zeroizing::new(
                self.algo
                    .cipher()
                    .decrypt_by_name("AES/OCB/NoPadding", &self.params(count, None), chunk)
                    .map_err(authentication)?,
            );
            if decoded.len() != chunk.len() - OCB_TAG_LEN {
                return Err(invalid("invalid OpenPGP decrypted chunk length"));
            }
            plaintext.extend_from_slice(&decoded);
            count += 1;
        }
        let final_plaintext = Zeroizing::new(
            self.algo
                .cipher()
                .decrypt_by_name(
                    "AES/OCB/NoPadding",
                    &self.params(count, Some(plaintext.len() as u64)),
                    final_tag,
                )
                .map_err(authentication)?,
        );
        if !final_plaintext.is_empty() {
            return Err(invalid("invalid OpenPGP final authentication tag"));
        }
        Ok(plaintext)
    }
}

fn hkdf(
    algo: &dyn Algo,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut kdf = algo.kdf().get_by_name("HKDF-SHA256").map_err(crypto)?;
    kdf.init(&HkdfParamsOwned::new(
        ikm.to_vec(),
        salt.to_vec(),
        info.to_vec(),
    ))
    .map_err(crypto)?;
    let mut output = Zeroizing::new(vec![0; length]);
    if kdf.generate_bytes(&mut output).map_err(crypto)? != length {
        return Err(io::Error::other("HKDF returned an invalid output length"));
    }
    Ok(output)
}

fn public_key(key: &PgpPublicKey) -> io::Result<&X25519PublicKey> {
    if key.version() != PublicKeyVersion::V6 || key.algorithm() != PublicKeyAlgorithmTag::X25519 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only v6 X25519 encryption keys are supported",
        ));
    }
    key.key()
        .as_any()
        .downcast_ref::<X25519PublicKey>()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid X25519 public key material",
            )
        })
}

fn read_array<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn crypto(error: AlgoError) -> io::Error {
    io::Error::other(error)
}

fn authentication(_: AlgoError) -> io::Error {
    invalid("OpenPGP message authentication failed")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
