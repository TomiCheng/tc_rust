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
        key::{KeyOwned, X25519PrivateKey, X25519PublicKey},
    },
};
use tc_openpgp_packet::{
    BodyLength, DecodingConfig, EncodingConfig, LiteralData, PacketTag, PgpReader, PgpWrite,
    PgpWriter, PublicKeyAlgorithmTag, PublicKeyVersion,
};
use tc_zeroize::Zeroizing;

use super::PgpEncryptedMessageProvider;
use crate::operator::kdf::hkdf;
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
        self.encrypt_to_many(&[recipient], data, output)
    }

    fn encrypt_to_many(
        &self,
        recipients: &[&PgpPublicKey],
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        if recipients.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected at least one recipient",
            ));
        }
        let mut session = Zeroizing::new([0; 16]);
        SysRng
            .try_fill_bytes(&mut session[..])
            .map_err(io::Error::other)?;
        let mut salt = [0; 32];
        SysRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;
        let pkesks = recipients
            .iter()
            .map(|key| self.wrap_session(key, &session))
            .collect::<io::Result<Vec<_>>>()?;
        let config = EncodingConfig::default();
        let plaintext_len = data.encode(&mut io::sink(), &config)?;
        let ocb = OcbMessage::new(&*self.algo, &session[..], &salt, CHUNK_SIZE_OCTET)?;
        let chunk_count = plaintext_len.div_ceil(ocb.chunk_size() as u64);
        let encrypted_len = plaintext_len + (chunk_count + 1) * OCB_TAG_LEN as u64 + 36;
        let encrypted_len = u32::try_from(encrypted_len)
            .map_err(|_| invalid("encrypted OpenPGP message is too long"))?;

        let mut packets = PgpWriter::new(output);
        for fields in pkesks {
            let mut pkesk = packets.write_body(
                PacketTag::PublicKeyEncryptedSession,
                BodyLength::Fixed(PKESK_LEN),
            )?;
            pkesk.write_all(&fields)?;
            pkesk.finish()?;
        }

        let mut body = packets.write_body(
            PacketTag::SymmetricEncryptedIntegrityProtected,
            BodyLength::Fixed(encrypted_len),
        )?;
        body.write_all(&ocb.aad[1..])?;
        body.write_all(&salt)?;
        let mut chunks = OcbChunkWriter::new(&ocb, &mut body);
        data.encode(&mut chunks, &config)?;
        chunks.finish(plaintext_len)?;
        body.finish()
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
        let fingerprint = v6_fingerprint(&*self.algo, recipient.public())?;
        let mut session = None;
        let mut body = loop {
            let (header, mut body) = reader.read_body(config)?;
            if header.tag() == PacketTag::SymmetricEncryptedIntegrityProtected
                && header.body_length() != BodyLength::Indeterminate
            {
                break body;
            }
            if header.tag() != PacketTag::PublicKeyEncryptedSession
                || !matches!(header.body_length(), BodyLength::Fixed(_))
            {
                return Err(invalid(
                    "expected a session key or integrity-protected data packet",
                ));
            }
            if session.is_some() || header.body_length() != BodyLength::Fixed(PKESK_LEN) {
                io::copy(&mut body, &mut io::sink())?;
                continue;
            }
            let fields: [u8; PKESK_LEN as usize] = read_array(&mut body)?;
            if fields[..3] == [6, 33, 6]
                && fields[3..35] == fingerprint
                && fields[35] == 25
                && fields[68] == 24
            {
                session = Some(self.unwrap_session(private, public, &fields)?);
            }
        };
        let session =
            session.ok_or_else(|| invalid("OpenPGP message is for a different recipient"))?;
        let [version, cipher, mode, chunk_size] = read_array(&mut body)?;
        if [version, cipher, mode] != [2, AES128, OCB] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only v2 AES-128/OCB messages are supported",
            ));
        }
        let salt: [u8; 32] = read_array(&mut body)?;
        let ocb = OcbMessage::new(&*self.algo, &session, &salt, chunk_size)?;
        let plaintext = ocb.open(&mut body)?;
        super::payload::decode(&plaintext, config, true)
    }
}

impl X25519EncryptedMessages {
    fn wrap_session(
        &self,
        recipient: &PgpPublicKey,
        session: &[u8; 16],
    ) -> io::Result<[u8; PKESK_LEN as usize]> {
        let public = public_key(recipient)?;
        let fingerprint = v6_fingerprint(&*self.algo, recipient)?;
        let mut scalar = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(&mut scalar[..])
            .map_err(io::Error::other)?;
        let ephemeral_private = X25519PrivateKey::new(*scalar);
        let ephemeral_public = ephemeral_private.generate_public_key();
        let kek = self.wrapping_key(&ephemeral_private, public, &ephemeral_public, public)?;
        let wrapped = self
            .algo
            .wrap()
            .wrap_by_name("AESWRAP", &kek, session)
            .map_err(crypto)?;
        if wrapped.len() != 24 {
            return Err(io::Error::other(
                "AES key wrap returned an invalid session key size",
            ));
        }
        let mut fields = [0; PKESK_LEN as usize];
        fields[..3].copy_from_slice(&[6, 33, 6]);
        fields[3..35].copy_from_slice(&fingerprint);
        fields[35] = 25;
        fields[36..68].copy_from_slice(ephemeral_public.u());
        fields[68] = 24;
        fields[69..].copy_from_slice(&wrapped);
        Ok(fields)
    }

    fn unwrap_session(
        &self,
        private: &X25519PrivateKey,
        public: &X25519PublicKey,
        fields: &[u8; PKESK_LEN as usize],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
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
        Ok(session)
    }

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

struct OcbChunkWriter<'a, 'b> {
    message: &'a OcbMessage<'b>,
    output: &'a mut dyn Write,
    chunk: Zeroizing<Vec<u8>>,
    used: usize,
    index: u64,
}

impl<'a, 'b> OcbChunkWriter<'a, 'b> {
    fn new(message: &'a OcbMessage<'b>, output: &'a mut dyn Write) -> Self {
        Self {
            message,
            output,
            chunk: Zeroizing::new(vec![0; message.chunk_size()]),
            used: 0,
            index: 0,
        }
    }

    fn seal_chunk(&mut self) -> io::Result<()> {
        self.output.write_all(
            &self
                .message
                .seal(self.index, None, &self.chunk[..self.used])?,
        )?;
        self.index += 1;
        self.used = 0;
        Ok(())
    }

    fn finish(mut self, plaintext_len: u64) -> io::Result<()> {
        if self.used != 0 {
            self.seal_chunk()?;
        }
        self.output
            .write_all(&self.message.seal(self.index, Some(plaintext_len), &[])?)
    }
}

impl Write for OcbChunkWriter<'_, '_> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let len = input.len();
        while !input.is_empty() {
            let count = input.len().min(self.chunk.len() - self.used);
            self.chunk[self.used..self.used + count].copy_from_slice(&input[..count]);
            self.used += count;
            input = &input[count..];
            if self.used == self.chunk.len() {
                self.seal_chunk()?;
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
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

    fn open(&self, mut input: &mut dyn Read) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut plaintext = Zeroizing::new(Vec::new());
        let mut lookahead = Vec::new();
        let mut count = 0;
        let read_size = self.chunk_size() + 2 * OCB_TAG_LEN;
        loop {
            let remaining = (read_size - lookahead.len()) as u64;
            (&mut input).take(remaining).read_to_end(&mut lookahead)?;
            if lookahead.len() == OCB_TAG_LEN && count != 0 {
                break;
            }
            if lookahead.len() <= 2 * OCB_TAG_LEN {
                return Err(invalid("missing or truncated OpenPGP encrypted chunk"));
            }
            let encrypted_len = lookahead.len() - OCB_TAG_LEN;
            let decoded = Zeroizing::new(
                self.algo
                    .cipher()
                    .decrypt_by_name(
                        "AES/OCB/NoPadding",
                        &self.params(count, None),
                        &lookahead[..encrypted_len],
                    )
                    .map_err(authentication)?,
            );
            if decoded.len() != encrypted_len - OCB_TAG_LEN {
                return Err(invalid("invalid OpenPGP decrypted chunk length"));
            }
            plaintext.extend_from_slice(&decoded);
            count += 1;
            lookahead.copy_within(encrypted_len.., 0);
            lookahead.truncate(OCB_TAG_LEN);
        }
        let final_plaintext = Zeroizing::new(
            self.algo
                .cipher()
                .decrypt_by_name(
                    "AES/OCB/NoPadding",
                    &self.params(count, Some(plaintext.len() as u64)),
                    &lookahead,
                )
                .map_err(authentication)?,
        );
        if !final_plaintext.is_empty() {
            return Err(invalid("invalid OpenPGP final authentication tag"));
        }
        Ok(plaintext)
    }
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
