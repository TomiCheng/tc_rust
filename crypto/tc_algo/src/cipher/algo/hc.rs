use tc_buffered_cipher::BufferedStreamCipher;

use super::stream::{Nonced, stream_row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of HC-128 and HC-256, as Bouncy Castle's CipherUtilities names them, with no OID. Each
// takes a key and an IV

#[cfg(feature = "hc128")]
pub(super) fn hc128(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["HC128"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(tc_hc::Hc128Engine::new())))
    })]
}

#[cfg(feature = "hc256")]
pub(super) fn hc256(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["HC256"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(tc_hc::Hc256Engine::new())))
    })]
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use tc_stream_cipher::{CipherDirection, KeyRef, KeyWithIvRef, StreamCipher, StreamCipherInit};

    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    #[allow(dead_code)]
    const MESSAGE: &[u8] = b"attack at dawn, then retreat at dusk";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[cfg(feature = "hc128")]
    #[test]
    fn hc128_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let _ = &iv;
        let mut engine = tc_hc::Hc128Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "HC128",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "HC128",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }

    #[cfg(feature = "hc256")]
    #[test]
    fn hc256_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let _ = &iv;
        let mut engine = tc_hc::Hc256Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "HC256",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "HC256",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }
}
