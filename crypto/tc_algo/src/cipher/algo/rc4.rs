use tc_buffered_cipher::BufferedStreamCipher;

#[cfg(any(feature = "rc4", feature = "isaac"))]
use super::stream::Keyed;
#[cfg(any(feature = "vmpc", feature = "vmpc-ksa3"))]
use super::stream::Nonced;
use super::stream::stream_row;
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of RC4 and its kin, to give to DefaultAlgoBuilder::reg_cipher. ARC4's names and OID are
// those of Bouncy Castle's CipherUtilities, as are VMPC's; ISAAC, which Bouncy Castle has as an
// engine but not there, has no alias or OID. RC4 and ISAAC take a key alone, VMPC a key and an IV

#[cfg(feature = "rc4")]
pub(super) fn rc4(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(
        &["ARC4", "RC4", "ARCFOUR"],
        &["1.2.840.113549.3.4"],
        || {
            Box::new(Keyed(BufferedStreamCipher::new(
                tc_rc4_family::Rc4Engine::new(),
            )))
        },
    )]
}

#[cfg(feature = "vmpc")]
pub(super) fn vmpc(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["VMPC", "VMPC-MAC"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(
            tc_rc4_family::VmpcEngine::new(),
        )))
    })]
}

#[cfg(feature = "vmpc-ksa3")]
pub(super) fn vmpc_ksa3(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["VMPC-KSA3"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(
            tc_rc4_family::VmpcKsa3Engine::new(),
        )))
    })]
}

#[cfg(feature = "isaac")]
pub(super) fn isaac(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["ISAAC"], &[], || {
        Box::new(Keyed(BufferedStreamCipher::new(
            tc_rc4_family::IsaacEngine::new(),
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

    // RFC 6229: the 40-bit key 0102030405, the keystream at offset 0
    #[cfg(feature = "rc4")]
    #[test]
    fn arc4_gives_the_keystream_of_rfc_6229_and_is_found_by_its_names() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("0102030405"));
        for name in ["ARC4", "RC4", "ARCFOUR"] {
            let output = algo.cipher().encrypt_by_name(name, &key, &[0; 16]).unwrap();
            assert_eq!(output, unhex("b2396305f03dc027ccc3524a0a1118a8"), "{name}");
        }
        let oid = "1.2.840.113549.3.4".parse().unwrap();
        let output = algo.cipher().encrypt_by_oid(&oid, &key, &[0; 16]).unwrap();
        assert_eq!(output, unhex("b2396305f03dc027ccc3524a0a1118a8"));
    }

    #[cfg(feature = "vmpc")]
    #[test]
    fn vmpc_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let _ = &iv;
        let mut engine = tc_rc4_family::VmpcEngine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "VMPC",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "VMPC",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }

    #[cfg(feature = "vmpc-ksa3")]
    #[test]
    fn vmpc_ksa3_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let _ = &iv;
        let mut engine = tc_rc4_family::VmpcKsa3Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "VMPC-KSA3",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "VMPC-KSA3",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }

    #[cfg(feature = "isaac")]
    #[test]
    fn isaac_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = unhex("");
        let _ = &iv;
        let mut engine = tc_rc4_family::IsaacEngine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&key))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name("ISAAC", &KeyOwned::new(key.clone()), MESSAGE)
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name("ISAAC", &KeyOwned::new(key.clone()), &output)
            .unwrap();
        assert_eq!(back, MESSAGE);
    }
}
