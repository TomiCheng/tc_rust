//! The three ChaCha variants through the RustCrypto `chacha20` crate.

use core::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher as _, StreamCipherSeek as _};
use chacha20::{ChaCha20, ChaCha20Legacy, XChaCha20};
use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

/// Defines one engine over a RustCrypto cipher type; the variants differ only
/// in that type, the IV length and the name.
macro_rules! rustcrypto_engine {
    (
        $(#[$meta:meta])*
        $name:ident($cipher:ty), iv_bytes: $iv_bytes:literal, algo_name: $algo_name:literal
    ) => {
        $(#[$meta])*
        pub struct $name {
            cipher: Option<$cipher>,
        }

        impl $name {
            /// Key length in bytes (256 bits).
            pub const KEY_BYTES: usize = 32;
            /// IV (nonce) length in bytes.
            pub const IV_BYTES: usize = $iv_bytes;

            /// An engine without a key; `init` must come before processing.
            /// Constant time.
            pub const fn new() -> Self {
                Self { cipher: None }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            /// Writes the algorithm name without inspecting key material.
            /// Constant time with respect to the key; output timing depends on
            /// the formatter.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($algo_name)
            }
        }

        impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for $name {
            type Error = InitError;

            /// Installs a 32-byte key and an IV of
            /// [`IV_BYTES`](Self::IV_BYTES) bytes, and starts the keystream at
            /// block zero. The direction is ignored: both directions apply the
            /// same keystream. A rejected length leaves the previous key, IV
            /// and position in place. Constant time; branches only on the
            /// lengths.
            fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
                let key = params.key();
                let iv = params.iv();
                if key.len() != Self::KEY_BYTES {
                    return Err(InitError::InvalidKeyLength(key.len()));
                }
                if iv.len() != Self::IV_BYTES {
                    return Err(InitError::InvalidIvLength(iv.len()));
                }
                // Both lengths were checked above, so this cannot fail.
                let cipher = <$cipher>::new_from_slices(key, iv)
                    .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
                self.cipher = Some(cipher);
                Ok(())
            }
        }

        impl StreamCipher for $name {
            type Error = StreamError;

            /// XORs `input` with the next keystream byte. Returns
            /// `NotInitialised` before `init`, and `CounterExhausted` once the
            /// keystream for this key and IV is used up. Constant time.
            fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let mut byte = [input];
                cipher
                    .try_apply_keystream(&mut byte)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(byte[0])
            }

            /// XORs `input` with the keystream into the start of `output` and
            /// returns `input.len()`; any longer tail of `output` is left
            /// untouched. Returns `NotInitialised` before `init`,
            /// `BufferTooShort` if `output` is shorter than `input`, and
            /// `CounterExhausted` if `input` would run past the end of the
            /// keystream. Errors leave `output` and the position unchanged.
            /// Constant time; branches only on the lengths.
            fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let output = output
                    .get_mut(..input.len())
                    .ok_or(StreamError::BufferTooShort)?;
                cipher
                    .try_apply_keystream_b2b(input, output)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(input.len())
            }

            /// Returns to the start of the keystream for the current key and
            /// IV; does nothing before `init`. Constant time.
            fn reset(&mut self) {
                if let Some(cipher) = &mut self.cipher {
                    cipher.seek(0u64);
                }
            }
        }
    };
}

rustcrypto_engine! {
    /// The original ChaCha20 (Bernstein, 2008): a 64-bit nonce and a 64-bit
    /// block counter, through RustCrypto's `ChaCha20Legacy`.
    ///
    /// Only 32-byte keys and 20 rounds: RustCrypto has neither the 16-byte key
    /// nor the reduced-round forms of the original layout.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    ChaChaRustCryptoEngine(ChaCha20Legacy), iv_bytes: 8, algo_name: "ChaCha20"
}

rustcrypto_engine! {
    /// IETF ChaCha20 (RFC 8439): a 96-bit nonce and a 32-bit block counter,
    /// through RustCrypto's `ChaCha20`.
    ///
    /// One key and nonce give at most 2^32 blocks (256 GiB); past that,
    /// processing returns `CounterExhausted`. The keystream starts at block
    /// zero, whereas RFC 8439's encryption examples start at block one.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    ChaCha7539RustCryptoEngine(ChaCha20), iv_bytes: 12, algo_name: "ChaCha7539"
}

rustcrypto_engine! {
    /// XChaCha20: HChaCha20 derives a subkey from the key and the first 16
    /// nonce bytes, then IETF ChaCha20 runs on the rest, through RustCrypto's
    /// `XChaCha20`. The 192-bit nonce is long enough to choose at random.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    XChaCha20RustCryptoEngine(XChaCha20), iv_bytes: 24, algo_name: "XChaCha20"
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::fmt::Display;

    use tc_stream_cipher::{
        CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit,
        StreamError,
    };

    use super::{ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine};

    /// Borrowed key and IV; `tc_stream_cipher` has no container yet.
    struct KeyIv<'a> {
        key: &'a [u8],
        iv: &'a [u8],
    }

    impl KeyParams for KeyIv<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl IvParams for KeyIv<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    trait Engine:
        Display
        + StreamCipher<Error = StreamError>
        + for<'a> StreamCipherInit<KeyIv<'a>, Error = InitError>
    {
    }

    impl<E> Engine for E where
        E: Display
            + StreamCipher<Error = StreamError>
            + for<'a> StreamCipherInit<KeyIv<'a>, Error = InitError>
    {
    }

    fn unhex(value: &str) -> Vec<u8> {
        let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn keystream<E: Engine>(mut engine: E, key: &[u8], iv: &[u8], length: usize) -> Vec<u8> {
        engine
            .init(CipherDirection::Encrypt, &KeyIv { key, iv })
            .unwrap();
        let mut output = vec![0u8; length];
        engine
            .process_bytes(&vec![0u8; length], &mut output)
            .unwrap();
        output
    }

    /// Checks the shared contract for an engine taking `iv_bytes`-byte IVs.
    fn check_contract<E: Engine>(new: fn() -> E, iv_bytes: usize, algo_name: &str) {
        let key = [0x11; 32];
        let iv = [0x22; 24];
        let params = KeyIv {
            key: &key,
            iv: &iv[..iv_bytes],
        };
        let input = [0x5a; 193];

        let mut engine = new();
        assert_eq!(engine.to_string(), algo_name);
        let mut untouched = [0x55; 4];
        assert_eq!(
            engine.process_bytes(&[0; 4], &mut untouched),
            Err(StreamError::NotInitialised)
        );
        assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
        assert_eq!(untouched, [0x55; 4]);

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut bulk = [0u8; 193];
        assert_eq!(engine.process_bytes(&input, &mut bulk), Ok(193));

        engine.reset();
        let mut chunked = [0u8; 193];
        engine
            .process_bytes(&input[..13], &mut chunked[..13])
            .unwrap();
        engine
            .process_bytes(&input[13..], &mut chunked[13..])
            .unwrap();
        assert_eq!(chunked, bulk);

        engine.reset();
        let single: Vec<u8> = input
            .iter()
            .map(|&byte| engine.return_byte(byte).unwrap())
            .collect();
        assert_eq!(single, bulk);

        engine.reset();
        let mut longer = [0x55; 200];
        assert_eq!(engine.process_bytes(&input, &mut longer), Ok(193));
        assert_eq!(&longer[..193], &bulk);
        assert_eq!(&longer[193..], &[0x55; 7]);

        engine.reset();
        let mut short = [0x55; 192];
        assert_eq!(
            engine.process_bytes(&input, &mut short),
            Err(StreamError::BufferTooShort)
        );
        assert_eq!(short, [0x55; 192]);

        // A rejected key or IV keeps the previous key, IV and position.
        let mut first = [0u8; 13];
        engine.process_bytes(&input[..13], &mut first).unwrap();
        for length in [0, 16, 31, 33] {
            let bad = KeyIv {
                key: &[0; 33][..length],
                iv: &iv[..iv_bytes],
            };
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &bad),
                Err(InitError::InvalidKeyLength(length))
            );
        }
        for length in [0, iv_bytes - 1, iv_bytes + 1] {
            let bad = KeyIv {
                key: &key,
                iv: &[0; 25][..length],
            };
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &bad),
                Err(InitError::InvalidIvLength(length))
            );
        }
        let mut rest = [0u8; 180];
        engine.process_bytes(&input[13..], &mut rest).unwrap();
        assert_eq!(&first, &bulk[..13]);
        assert_eq!(&rest, &bulk[13..]);

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = [0u8; 193];
        engine.process_bytes(&bulk, &mut recovered).unwrap();
        assert_eq!(recovered, input);

        let mut boxed: Box<dyn StreamCipher<Error = StreamError>> = Box::new(engine);
        boxed.reset();
        assert_eq!(boxed.return_byte(input[0]), Ok(bulk[0]));
    }

    #[test]
    fn every_engine_keeps_state_on_errors_and_matches_across_chunking_and_directions() {
        check_contract(ChaChaRustCryptoEngine::new, 8, "ChaCha20");
        check_contract(ChaCha7539RustCryptoEngine::new, 12, "ChaCha7539");
        check_contract(XChaCha20RustCryptoEngine::new, 24, "XChaCha20");
    }

    #[test]
    fn the_original_chacha20_engine_matches_the_bouncy_castle_256_bit_key_vector() {
        let key = unhex(
            "0053A6F94C9FF24598EB3E91E4378ADD
             3083D6297CCF2275C81B6EC11467BA0D",
        );
        let iv = unhex("0D74DB42A91077DE");
        let stream = keystream(ChaChaRustCryptoEngine::new(), &key, &iv, 65_600);
        assert_eq!(
            &stream[..64],
            unhex(
                "57459975BC46799394788DE80B928387
                 862985A269B9E8E77801DE9D874B3F51
                 AC4610B9F9BEE8CF8CACD8B5AD0BF17D
                 3DDF23FD7424887EB3F81405BD498CC3"
            )
        );
        assert_eq!(
            &stream[65_472..65_536],
            unhex(
                "EF9AEC58ACE7DB427DF012B2B91A0C1E
                 8E4759DCE9CDB00A2BD59207357BA06C
                 E02D327C7719E83D6348A6104B081DB0
                 3908E5186986AE41E3AE95298BB7B713"
            )
        );
        assert_eq!(
            &stream[65_536..65_600],
            unhex(
                "17EF5FF454D85ABBBA280F3A94F1D26E
                 950C7D5B05C4BB3A78326E0DC5731F83
                 84205C32DB867D1B476CE121A0D7074B
                 AA7EE90525D15300F48EC0A6624BD0AF"
            )
        );
    }

    #[test]
    fn the_ietf_engine_matches_the_rfc_8439_encryption_vector_from_block_one() {
        let key = unhex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
        let iv = unhex("000000000000004a00000000");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = unhex(
            "6e2e359a2568f98041ba0728dd0d6981
             e97e7aec1d4360c20a27afccfd9fae0b
             f91b65c5524733ab8f593dabcd62b357
             1639d624e65152ab8f530c359f0861d8
             07ca0dbf500d6a6156a38e088a22b65e
             52bc514d16ccf806818ce91ab7793736
             5af90bbf74a35be6b40b8eedf2785e42
             874d",
        );
        let stream = keystream(
            ChaCha7539RustCryptoEngine::new(),
            &key,
            &iv,
            64 + plaintext.len(),
        );
        let ciphertext: Vec<u8> = stream[64..]
            .iter()
            .zip(plaintext)
            .map(|(k, p)| k ^ p)
            .collect();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn the_xchacha20_engine_matches_the_draft_vector_from_block_one() {
        let key = unhex("808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f");
        let iv = unhex("404142434445464748494a4b4c4d4e4f 5051525354555657");
        let plaintext = unhex(
            "4c616469657320616e642047656e746c
             656d656e206f662074686520636c6173
             73206f66202739393a20496620492063
             6f756c64206f6666657220796f75206f
             6e6c79206f6e652074697020666f7220
             746865206675747572652c2073756e73
             637265656e20776f756c642062652069
             742e",
        );
        let expected = unhex(
            "bd6d179d3e83d43b9576579493c0e939
             572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39
             ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e
             3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13
             b52e",
        );
        let stream = keystream(
            XChaCha20RustCryptoEngine::new(),
            &key,
            &iv,
            64 + plaintext.len(),
        );
        let ciphertext: Vec<u8> = stream[64..]
            .iter()
            .zip(&plaintext)
            .map(|(k, p)| k ^ p)
            .collect();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn the_wrapped_rustcrypto_ciphers_wipe_their_state_and_buffered_keystream_on_drop() {
        fn wiped_on_drop<T: cipher::zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<chacha20::ChaCha20Legacy>();
        wiped_on_drop::<chacha20::ChaCha20>();
        wiped_on_drop::<chacha20::XChaCha20>();
    }
}
