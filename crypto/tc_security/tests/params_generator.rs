#![cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "camellia",
    feature = "des",
    feature = "desede",
    feature = "rc2",
    feature = "rc5",
    feature = "rc6",
    feature = "chacha",
    feature = "ascon"
))]

use tc_security::cipher::{self, Algorithm, CipherEntry, Mode, Padding};
use tc_security::params::{self, AnyParams};

#[allow(unreachable_code, reason = "沒開區塊加密演算法時 match 沒有分支")]
fn key_for(entry: &CipherEntry) -> AnyParams {
    let len = match entry.algo() {
        #[cfg(feature = "aes")]
        Algorithm::Aes => 16,
        #[cfg(feature = "aria")]
        Algorithm::Aria => 16,
        #[cfg(feature = "camellia")]
        Algorithm::Camellia => 16,
        #[cfg(feature = "des")]
        Algorithm::Des => 8,
        #[cfg(feature = "desede")]
        Algorithm::DesEde => 24,
        #[cfg(feature = "rc2")]
        Algorithm::Rc2 => 16,
        #[cfg(feature = "rc5")]
        Algorithm::Rc5 | Algorithm::Rc5_64 => 16,
        #[cfg(feature = "rc6")]
        Algorithm::Rc6 => 16,
        #[cfg(feature = "chacha")]
        Algorithm::ChaCha | Algorithm::ChaCha7539 | Algorithm::XChaCha20 => 32,
        #[cfg(feature = "ascon")]
        Algorithm::AsconAead128 | Algorithm::Ascon128 | Algorithm::Ascon128a => 16,
        #[cfg(feature = "ascon")]
        Algorithm::Ascon80pq => 20,
        _ => panic!("{entry}: add the key length of this algorithm"),
    };
    AnyParams::new(vec![7; len])
}

#[test]
fn every_combination_encrypts_and_decrypts_with_generated_parameters() {
    for entry in cipher::algorithms() {
        #[cfg(feature = "rsa")]
        if entry.algo() == Algorithm::Rsa {
            continue;
        }
        #[cfg(feature = "ecies")]
        if entry.algo() == Algorithm::Ecies {
            continue;
        }
        let params = params::get_by_name(entry.name())
            .unwrap()
            .generator(key_for(entry))
            .generate()
            .unwrap();
        let unpadded_block_mode = matches!(entry.mode(), Some(Mode::Ecb | Mode::Cbc))
            && entry.padding() == Some(Padding::NoPadding);
        let message: &[u8] = if unpadded_block_mode {
            &[0x5a; 32]
        } else {
            &[0x5a; 37]
        };

        let mut cipher = entry.cipher();
        let sealed = cipher::encrypt(&mut cipher, &params, message).unwrap();
        assert_eq!(
            cipher::decrypt(&mut cipher, &params, &sealed).unwrap(),
            message,
            "{entry}"
        );
    }
}

#[cfg(feature = "aes")]
#[test]
fn cbc_gets_a_fresh_iv_of_one_block_each_time_with_the_same_key() {
    use tc_block_cipher::KeyParams;
    use tc_block_modes::IvParams;

    let mut generator = params::get_by_name("AES/CBC/PKCS7Padding")
        .unwrap()
        .generator(AnyParams::new(vec![7; 16]));
    let first = generator.generate().unwrap();
    let second = generator.generate().unwrap();
    assert_eq!(IvParams::iv(&first).len(), 16);
    assert_ne!(IvParams::iv(&first), IvParams::iv(&second));
    assert_eq!(KeyParams::key(&first), [7; 16]);
    assert_eq!(KeyParams::key(&second), [7; 16]);
}

#[cfg(feature = "aes")]
#[test]
fn aead_modes_get_a_nonce_and_a_tag_size_as_in_bc() {
    use tc_aead_cipher::{MacSizeParams, NonceParams};

    for (name, nonce, tag) in [
        ("AES/GCM", 12, 16),
        ("AES/CCM", 12, 16),
        ("AES/OCB", 12, 16),
        ("AES/EAX", 16, 8),
    ] {
        let params = params::get_by_name(name)
            .unwrap()
            .generator(AnyParams::new(vec![7; 16]))
            .generate()
            .unwrap();
        assert!(matches!(params, AnyParams::Aead { .. }), "{name}");
        assert_eq!(params.nonce().len(), nonce, "{name}");
        assert_eq!(params.mac_size(), tag, "{name}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn ecb_passes_the_key_on_without_an_iv() {
    let params = params::get_by_name("AES")
        .unwrap()
        .generator(AnyParams::new(vec![7; 16]))
        .generate()
        .unwrap();
    assert!(matches!(params, AnyParams::Key { .. }));
}

#[cfg(feature = "aes")]
#[test]
fn ivs_come_from_the_given_rng() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_block_modes::IvParams;

    let iv = |seed| {
        let mut generator = params::get_by_name("AES/CBC")
            .unwrap()
            .generator(AnyParams::new(vec![7; 16]));
        generator.with_rng(StdRng::seed_from_u64(seed));
        IvParams::iv(&generator.generate().unwrap()).to_vec()
    };
    assert_eq!(iv(1), iv(1));
    assert_ne!(iv(1), iv(2));
}

#[cfg(feature = "rc2")]
#[test]
fn eax_over_an_eight_byte_block_gets_a_half_block_tag() {
    use tc_aead_cipher::{MacSizeParams, NonceParams};

    let params = params::get_by_name("RC2/EAX")
        .unwrap()
        .generator(AnyParams::new(vec![7; 16]))
        .generate()
        .unwrap();
    assert_eq!(params.nonce().len(), 8);
    assert_eq!(params.mac_size(), 4);
}

#[cfg(feature = "chacha")]
#[test]
fn stream_ciphers_get_the_nonce_length_of_each_variant() {
    use tc_block_modes::IvParams;

    for (name, nonce) in [("CHACHA", 8), ("CHACHA7539", 12), ("XCHACHA20", 24)] {
        let params = params::get_by_name(name)
            .unwrap()
            .generator(AnyParams::new(vec![7; 32]))
            .generate()
            .unwrap();
        assert_eq!(IvParams::iv(&params).len(), nonce, "{name}");
    }
}
