#[cfg(feature = "chacha-aead")]
use tc_chacha_aead::ChaCha20Poly1305Engine;
#[cfg(feature = "chacha-aead")]
use tc_chacha_aead::XChaCha20Poly1305Engine;

use super::aead_engine::{AeadEngine, row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// ChaCha20-Poly1305 of RFC 8439, as Bouncy Castle's CipherUtilities names it, with the OID of RFC
// 8103 that it gives the same row
#[cfg(feature = "chacha-aead")]
pub(super) fn chacha20_poly1305(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row(
        "CHACHA20-POLY1305",
        &["1.2.840.113549.1.9.16.3.18"],
        || Box::new(AeadEngine(ChaCha20Poly1305Engine::new())),
    )]
}

// XChaCha20-Poly1305, its extension to a nonce of 24 bytes, as Bouncy Castle names it, with no OID
#[cfg(feature = "chacha-aead")]
pub(super) fn xchacha20_poly1305(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("XCHACHA20-POLY1305", &[], || {
        Box::new(AeadEngine(XChaCha20Poly1305Engine::new()))
    })]
}

#[cfg(test)]
mod tests {
    use crate::params::cipher::AeadParamsOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8439, section 2.8.2: the sunscreen message, sealed with its tag
    #[cfg(feature = "chacha-aead")]
    #[test]
    fn chacha20_poly1305_gives_the_example_of_rfc_8439() {
        let params = AeadParamsOwned::new(
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            unhex("070000004041424344454647"),
            16,
            unhex("50515253c0c1c2c3c4c5c6c7"),
        );
        let message = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let sealed = ciphers
            .encrypt_by_name("ChaCha20-Poly1305", &params, message)
            .unwrap();
        assert_eq!(
            &sealed[message.len()..],
            unhex("1ae10b594f09e26a7e902ecbd0600691").as_slice()
        );
        assert_eq!(
            &sealed[..16],
            unhex("d31a8d34648e60db7b86afbc53ef7ec2").as_slice()
        );
        let opened = ciphers
            .decrypt_by_name("CHACHA20-POLY1305", &params, &sealed)
            .unwrap();
        assert_eq!(opened, message);

        let by_oid = ciphers
            .get_by_oid(&"1.2.840.113549.1.9.16.3.18".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 0);

        let mut changed = sealed.clone();
        changed[0] ^= 1;
        let error = ciphers
            .decrypt_by_name("CHACHA20-POLY1305", &params, &changed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    // A nonce of 24 bytes, which may be drawn at random; one of 12 is refused
    #[cfg(feature = "chacha-aead")]
    #[test]
    fn xchacha20_poly1305_takes_a_nonce_of_24_bytes_and_decrypts_back() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = AeadParamsOwned::new(vec![0x42; 32], vec![0x24; 24], 16, b"aad".to_vec());
        let sealed = ciphers
            .encrypt_by_name("XCHACHA20-POLY1305", &params, b"message")
            .unwrap();
        assert_eq!(sealed.len(), 7 + 16);
        let opened = ciphers
            .decrypt_by_name("xchacha20-poly1305", &params, &sealed)
            .unwrap();
        assert_eq!(opened, b"message");

        let short = AeadParamsOwned::new(vec![0x42; 32], vec![0x24; 12], 16, Vec::new());
        let error = ciphers
            .encrypt_by_name("XCHACHA20-POLY1305", &short, b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
