use tc_buffered_cipher::BufferedStreamCipher;

use super::stream::{Nonced, stream_row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Salsa20, with a nonce of 8 bytes, as Bouncy Castle's CipherUtilities names it, and
// of XSalsa20, with a nonce of 24, which it has as an engine but not there. Neither has an OID

#[cfg(feature = "salsa20")]
pub(super) fn salsa20(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["SALSA20"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(
            tc_salsa20::Salsa20Engine::new(),
        )))
    })]
}

#[cfg(feature = "xsalsa20")]
pub(super) fn xsalsa20(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["XSALSA20"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(
            tc_salsa20::Xsalsa20Engine::new(),
        )))
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

    #[cfg(feature = "salsa20")]
    #[test]
    fn salsa20_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = unhex("0001020304050607");
        let _ = &iv;
        let mut engine = tc_salsa20::Salsa20Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "SALSA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "SALSA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }

    #[cfg(feature = "xsalsa20")]
    #[test]
    fn xsalsa20_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let _ = &iv;
        let mut engine = tc_salsa20::Xsalsa20Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "XSALSA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "XSALSA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }
}
