//! Raw Poly1305 engine.

use core::fmt;

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto_core::{Key, Mac, MacInit};

use super::{BLOCK_BYTES, CipherParams, KEY_BYTES, TAG_BYTES};

const LIMB_MASK: u32 = 0x03ff_ffff;
const FULL_BLOCK_HIGH_BIT: u32 = 1 << 24;

/// Failures reported by raw Poly1305 operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The engine has not been initialized with a one-time key.
    NotInitialized,

    /// The supplied key is not 32 bytes long.
    InvalidKeyLength(usize),

    /// The output buffer cannot hold the 16-byte authentication tag.
    OutputTooShort {
        /// Required output length in bytes.
        required: usize,
        /// Supplied output length in bytes.
        actual: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("Poly1305 is not initialized"),
            Self::InvalidKeyLength(actual) => {
                write!(f, "Poly1305 requires a 32-byte key, got {actual}")
            }
            Self::OutputTooShort { required, actual } => write!(
                f,
                "output buffer is too short: required {required} bytes, got {actual}"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// Failures reported by Poly1305 with an underlying block cipher.
#[derive(Debug, Eq, PartialEq)]
pub enum CipherError<E> {
    /// The selected cipher does not have a 16-byte block size.
    InvalidBlockSize(usize),

    /// The cipher returned a block length other than 16 bytes.
    InvalidOutputSize(usize),

    /// The underlying block cipher failed.
    Cipher(E),

    /// The Poly1305 calculation failed.
    Poly1305(Error),
}

impl<E: fmt::Display> fmt::Display for CipherError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(actual) => {
                write!(f, "Poly1305 requires a 16-byte block cipher, got {actual}")
            }
            Self::InvalidOutputSize(actual) => {
                write!(f, "block cipher wrote {actual} bytes instead of 16")
            }
            Self::Cipher(error) => write!(f, "block cipher failed: {error}"),
            Self::Poly1305(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error> core::error::Error for CipherError<E> {}

/// Raw Poly1305 message authentication code.
///
/// Initialization takes a 32-byte one-time key directly. This engine does not
/// implement Bouncy Castle's optional block-cipher form of Poly1305.
///
/// # Security
///
/// A Poly1305 key must never authenticate two different messages. For
/// compatibility with [`Mac`], successful finalization and [`reset`](Mac::reset)
/// preserve the initialized key; callers are responsible for supplying a fresh
/// one-time key before authenticating another message.
pub struct Engine {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    k0: u32,
    k1: u32,
    k2: u32,
    k3: u32,
    block: [u8; BLOCK_BYTES],
    block_offset: usize,
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    initialized: bool,
}

impl Engine {
    /// Creates an uninitialized raw Poly1305 engine.
    pub const fn new() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            r4: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            k0: 0,
            k1: 0,
            k2: 0,
            k3: 0,
            block: [0; BLOCK_BYTES],
            block_offset: 0,
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            initialized: false,
        }
    }

    #[inline]
    fn load_u32(input: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ])
    }

    fn set_key(&mut self, key: &[u8; KEY_BYTES]) {
        let t0 = Self::load_u32(key, 0);
        let t1 = Self::load_u32(key, 4);
        let t2 = Self::load_u32(key, 8);
        let t3 = Self::load_u32(key, 12);

        // These masks perform the Poly1305 key clamp without modifying the
        // caller's key bytes.
        self.r0 = t0 & 0x03ff_ffff;
        self.r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
        self.r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
        self.r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
        self.r4 = (t3 >> 8) & 0x000f_ffff;

        self.s1 = self.r1 * 5;
        self.s2 = self.r2 * 5;
        self.s3 = self.r3 * 5;
        self.s4 = self.r4 * 5;

        self.k0 = Self::load_u32(key, 16);
        self.k1 = Self::load_u32(key, 20);
        self.k2 = Self::load_u32(key, 24);
        self.k3 = Self::load_u32(key, 28);
    }

    fn process_block(&mut self, block: &[u8], high_bit: u32) {
        let t0 = Self::load_u32(block, 0);
        let t1 = Self::load_u32(block, 4);
        let t2 = Self::load_u32(block, 8);
        let t3 = Self::load_u32(block, 12);

        self.h0 += t0 & LIMB_MASK;
        self.h1 += ((t1 << 6) | (t0 >> 26)) & LIMB_MASK;
        self.h2 += ((t2 << 12) | (t1 >> 20)) & LIMB_MASK;
        self.h3 += ((t3 << 18) | (t2 >> 14)) & LIMB_MASK;
        self.h4 += high_bit | (t3 >> 8);

        let tp0 = u64::from(self.h0) * u64::from(self.r0)
            + u64::from(self.h1) * u64::from(self.s4)
            + u64::from(self.h2) * u64::from(self.s3)
            + u64::from(self.h3) * u64::from(self.s2)
            + u64::from(self.h4) * u64::from(self.s1);
        let mut tp1 = u64::from(self.h0) * u64::from(self.r1)
            + u64::from(self.h1) * u64::from(self.r0)
            + u64::from(self.h2) * u64::from(self.s4)
            + u64::from(self.h3) * u64::from(self.s3)
            + u64::from(self.h4) * u64::from(self.s2);
        let mut tp2 = u64::from(self.h0) * u64::from(self.r2)
            + u64::from(self.h1) * u64::from(self.r1)
            + u64::from(self.h2) * u64::from(self.r0)
            + u64::from(self.h3) * u64::from(self.s4)
            + u64::from(self.h4) * u64::from(self.s3);
        let mut tp3 = u64::from(self.h0) * u64::from(self.r3)
            + u64::from(self.h1) * u64::from(self.r2)
            + u64::from(self.h2) * u64::from(self.r1)
            + u64::from(self.h3) * u64::from(self.r0)
            + u64::from(self.h4) * u64::from(self.s4);
        let mut tp4 = u64::from(self.h0) * u64::from(self.r4)
            + u64::from(self.h1) * u64::from(self.r3)
            + u64::from(self.h2) * u64::from(self.r2)
            + u64::from(self.h3) * u64::from(self.r1)
            + u64::from(self.h4) * u64::from(self.r0);

        self.h0 = tp0 as u32 & LIMB_MASK;
        tp1 += tp0 >> 26;
        self.h1 = tp1 as u32 & LIMB_MASK;
        tp2 += tp1 >> 26;
        self.h2 = tp2 as u32 & LIMB_MASK;
        tp3 += tp2 >> 26;
        self.h3 = tp3 as u32 & LIMB_MASK;
        tp4 += tp3 >> 26;
        self.h4 = tp4 as u32 & LIMB_MASK;
        self.h0 += (tp4 >> 26) as u32 * 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
    }

    fn write_tag(&mut self, output: &mut [u8]) {
        self.h0 += 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
        self.h2 += self.h1 >> 26;
        self.h1 &= LIMB_MASK;
        self.h3 += self.h2 >> 26;
        self.h2 &= LIMB_MASK;
        self.h4 += self.h3 >> 26;
        self.h3 &= LIMB_MASK;

        let mut carry = (i64::from(self.h4 >> 26) - 1) * 5;
        carry += i64::from(self.k0) + i64::from(self.h0 | (self.h1 << 26));
        output[..4].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k1) + i64::from((self.h1 >> 6) | (self.h2 << 20));
        output[4..8].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k2) + i64::from((self.h2 >> 12) | (self.h3 << 14));
        output[8..12].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k3) + i64::from((self.h3 >> 18) | (self.h4 << 8));
        output[12..TAG_BYTES].copy_from_slice(&(carry as u32).to_le_bytes());
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Mac for Engine {
    type Error = Error;

    fn algorithm_name(&self) -> &str {
        "Poly1305"
    }

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }

        if self.block_offset != 0 {
            let available = BLOCK_BYTES - self.block_offset;
            let take = available.min(input.len());
            self.block[self.block_offset..self.block_offset + take].copy_from_slice(&input[..take]);
            self.block_offset += take;
            input = &input[take..];

            if self.block_offset < BLOCK_BYTES {
                return Ok(());
            }

            let block = self.block;
            self.process_block(&block, FULL_BLOCK_HIGH_BIT);
            self.block_offset = 0;
        }

        while input.len() >= BLOCK_BYTES {
            self.process_block(&input[..BLOCK_BYTES], FULL_BLOCK_HIGH_BIT);
            input = &input[BLOCK_BYTES..];
        }

        self.block[..input.len()].copy_from_slice(input);
        self.block_offset = input.len();
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        if output.len() < TAG_BYTES {
            return Err(Error::OutputTooShort {
                required: TAG_BYTES,
                actual: output.len(),
            });
        }

        if self.block_offset != 0 {
            let mut block = self.block;
            block[self.block_offset] = 1;
            block[self.block_offset + 1..].fill(0);
            self.process_block(&block, 0);
        }

        debug_assert_eq!(self.h4 >> 26, 0);
        self.write_tag(output);
        self.reset();
        Ok(TAG_BYTES)
    }

    fn reset(&mut self) {
        self.block.fill(0);
        self.block_offset = 0;
        self.h0 = 0;
        self.h1 = 0;
        self.h2 = 0;
        self.h3 = 0;
        self.h4 = 0;
    }
}

impl MacInit for Engine {
    type Params<'a> = dyn Key + 'a;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset();

        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| Error::InvalidKeyLength(key.len()))?;

        self.set_key(key);
        self.initialized = true;
        self.reset();
        Ok(())
    }
}

/// Poly1305 using a 128-bit block cipher to derive the final 16 key bytes.
///
/// During initialization, the cipher is keyed with the last 16 bytes of the
/// Poly1305 key and encrypts the 16-byte nonce. The encrypted nonce becomes the
/// additive half of the effective raw Poly1305 one-time key.
pub struct CipherEngine<C> {
    inner: Engine,
    cipher: C,
}

impl<C: BlockCipher> CipherEngine<C> {
    /// Creates an uninitialized Poly1305 engine around `cipher`.
    pub fn new(cipher: C) -> Result<Self, CipherError<C::Error>> {
        let block_size = cipher.block_size();
        if block_size != BLOCK_BYTES {
            return Err(CipherError::InvalidBlockSize(block_size));
        }

        Ok(Self {
            inner: Engine::new(),
            cipher,
        })
    }

    /// Returns the wrapped block cipher.
    pub fn into_cipher(self) -> C {
        self.cipher
    }
}

impl<C: BlockCipher> Mac for CipherEngine<C> {
    type Error = CipherError<C::Error>;

    fn algorithm_name(&self) -> &str {
        "Poly1305-Cipher"
    }

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.inner.update(input).map_err(CipherError::Poly1305)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.do_final(output).map_err(CipherError::Poly1305)
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<C: BlockCipherInit> MacInit for CipherEngine<C> {
    type Params<'a> = CipherParams<'a, C::Params<'a>>;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.inner.initialized = false;
        self.inner.reset();

        self.cipher
            .init(CipherDirection::Encrypt, params.cipher_params())
            .map_err(CipherError::Cipher)?;

        let mut encrypted_nonce = [0_u8; BLOCK_BYTES];
        let written = match self.cipher.process_block(params.iv(), &mut encrypted_nonce) {
            Ok(written) => written,
            Err(error) => {
                encrypted_nonce.fill(0);
                return Err(CipherError::Cipher(error));
            }
        };
        if written != BLOCK_BYTES {
            encrypted_nonce.fill(0);
            return Err(CipherError::InvalidOutputSize(written));
        }

        let mut effective_key = *params.key();
        effective_key[KEY_BYTES - BLOCK_BYTES..].copy_from_slice(&encrypted_nonce);
        self.inner.set_key(&effective_key);
        self.inner.initialized = true;
        self.inner.reset();
        encrypted_nonce.fill(0);
        effective_key.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly1305::{BorrowedParams, CipherParams, NONCE_BYTES};
    use tc_block_cipher::{AesEngine, AesParams, DesEngine};

    const RFC_KEY: [u8; KEY_BYTES] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    const RFC_MESSAGE: &[u8] = b"Cryptographic Forum Research Group";
    const RFC_TAG: [u8; TAG_BYTES] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];

    fn initialized(key: &[u8; KEY_BYTES]) -> Engine {
        let mut engine = Engine::new();
        engine.init(&BorrowedParams::new(key)).unwrap();
        engine
    }

    fn authenticate(key: &[u8; KEY_BYTES], message: &[u8]) -> [u8; TAG_BYTES] {
        let mut engine = initialized(key);
        let mut tag = [0_u8; TAG_BYTES];
        engine.update(message).unwrap();
        engine.do_final(&mut tag).unwrap();
        tag
    }

    #[test]
    fn matches_rfc_8439_vector() {
        let mut engine = initialized(&RFC_KEY);
        engine.update(RFC_MESSAGE).unwrap();
        let mut tag = [0_u8; TAG_BYTES];

        assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
        assert_eq!(tag, RFC_TAG);
    }

    #[test]
    fn every_chunk_size_matches_rfc_vector() {
        for chunk_size in 1..=RFC_MESSAGE.len() {
            let mut engine = initialized(&RFC_KEY);
            for chunk in RFC_MESSAGE.chunks(chunk_size) {
                engine.update(chunk).unwrap();
            }

            let mut tag = [0_u8; TAG_BYTES];
            engine.do_final(&mut tag).unwrap();
            assert_eq!(tag, RFC_TAG, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn matches_rfc_8439_reduction_edge_vectors() {
        let mut key = [0_u8; KEY_BYTES];
        let mut message = [0xff_u8; BLOCK_BYTES];
        key[0] = 2;
        assert_eq!(
            authenticate(&key, &message),
            [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        key[16..].fill(0xff);
        message.fill(0);
        message[0] = 2;
        assert_eq!(
            authenticate(&key, &message),
            [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        key.fill(0);
        key[0] = 2;
        message.fill(0xff);
        message[0] = 0xfd;
        assert_eq!(
            authenticate(&key, &message),
            [
                0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ]
        );
    }

    #[test]
    fn empty_message_tag_is_key_s_half() {
        let mut engine = initialized(&RFC_KEY);
        let mut tag = [0_u8; TAG_BYTES];

        engine.do_final(&mut tag).unwrap();
        assert_eq!(tag, RFC_KEY[16..]);
    }

    #[test]
    fn reports_state_and_output_errors_without_consuming_message() {
        let mut engine = Engine::new();
        assert_eq!(engine.update(b"message"), Err(Error::NotInitialized));
        assert_eq!(engine.do_final(&mut []), Err(Error::NotInitialized));

        engine.init(&BorrowedParams::new(&RFC_KEY)).unwrap();
        engine.update(RFC_MESSAGE).unwrap();
        assert_eq!(
            engine.do_final(&mut [0_u8; TAG_BYTES - 1]),
            Err(Error::OutputTooShort {
                required: TAG_BYTES,
                actual: TAG_BYTES - 1,
            })
        );

        let mut tag = [0_u8; TAG_BYTES];
        engine.do_final(&mut tag).unwrap();
        assert_eq!(tag, RFC_TAG);
    }

    #[test]
    fn accepts_any_key_implementation_and_rejects_wrong_length() {
        struct TestKey<'a>(&'a [u8]);

        impl Key for TestKey<'_> {
            fn key(&self) -> &[u8] {
                self.0
            }
        }

        let mut engine = Engine::new();
        engine.init(&TestKey(&RFC_KEY)).unwrap();
        engine.update(RFC_MESSAGE).unwrap();
        let mut tag = [0_u8; TAG_BYTES];
        engine.do_final(&mut tag).unwrap();
        assert_eq!(tag, RFC_TAG);

        assert_eq!(
            engine.init(&TestKey(&RFC_KEY[..KEY_BYTES - 1])),
            Err(Error::InvalidKeyLength(KEY_BYTES - 1))
        );
        assert_eq!(engine.update(RFC_MESSAGE), Err(Error::NotInitialized));
    }

    #[test]
    fn do_final_and_reset_preserve_initialized_key() {
        let mut engine = initialized(&RFC_KEY);
        let mut first = [0_u8; TAG_BYTES];
        let mut second = [0_u8; TAG_BYTES];

        engine.update(RFC_MESSAGE).unwrap();
        engine.do_final(&mut first).unwrap();
        engine.update(&[1, 2]).unwrap();
        engine.reset();
        engine.update(RFC_MESSAGE).unwrap();
        engine.do_final(&mut second).unwrap();

        assert_eq!(first, RFC_TAG);
        assert_eq!(second, RFC_TAG);
    }

    #[test]
    fn initialized_engine_supports_dynamic_dispatch() {
        let mut concrete = initialized(&RFC_KEY);
        let mac: &mut dyn Mac<Error = Error> = &mut concrete;
        let mut tag = [0_u8; TAG_BYTES];

        assert_eq!(mac.algorithm_name(), "Poly1305");
        assert_eq!(mac.mac_size(), TAG_BYTES);
        mac.update(RFC_MESSAGE).unwrap();
        mac.do_final(&mut tag).unwrap();
        assert_eq!(tag, RFC_TAG);
    }

    #[test]
    fn cipher_engine_matches_poly1305_aes_vectors() {
        const EMPTY_TAG: [u8; TAG_BYTES] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        let key = [0_u8; KEY_BYTES];
        let nonce = [0_u8; NONCE_BYTES];
        let params = CipherParams::try_new(&key, &nonce, |key| AesParams::new(key)).unwrap();
        let mut engine = CipherEngine::new(AesEngine::new()).unwrap();
        engine.init(&params).unwrap();
        let mut tag = [0_u8; TAG_BYTES];

        assert_eq!(engine.algorithm_name(), "Poly1305-Cipher");
        assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
        assert_eq!(tag, EMPTY_TAG);

        let key = [
            0xf7, 0x95, 0xbd, 0x0a, 0x50, 0xe2, 0x9e, 0x07, 0x10, 0xd3, 0x13, 0x0a, 0x20, 0xe9,
            0x8d, 0x0c, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa,
            0x20, 0xe9, 0x8d, 0xbc,
        ];
        let nonce = [
            0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec, 0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd,
            0xa6, 0x92,
        ];
        let params = CipherParams::try_new(&key, &nonce, |key| AesParams::new(key)).unwrap();
        engine.init(&params).unwrap();
        engine.update(&[0x66, 0xf7]).unwrap();
        engine.do_final(&mut tag).unwrap();
        assert_eq!(
            tag,
            [
                0x5c, 0xa5, 0x85, 0xc7, 0x5e, 0x8f, 0x8f, 0x02, 0x5e, 0x71, 0x0c, 0xab, 0xc9, 0xa1,
                0x50, 0x8b,
            ]
        );
    }

    #[test]
    fn cipher_engine_rejects_non_128_bit_block_cipher() {
        assert!(matches!(
            CipherEngine::new(DesEngine::new()),
            Err(CipherError::InvalidBlockSize(8))
        ));
    }
}
