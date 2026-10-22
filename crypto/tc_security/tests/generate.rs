//! 產生器的查詢：名稱、別名與 OID 找到對應的一列，名稱與 OID 不重複。

use std::collections::HashSet;

use tc_security::SecurityError;
use tc_security::generate;

fn name_of(name: &str) -> Result<&'static str, SecurityError> {
    generate::get_by_name(name).map(|entry| entry.name())
}

#[test]
fn every_entry_name_and_oid_is_unique() {
    let mut names = HashSet::new();
    let mut oids = HashSet::new();
    for entry in generate::algorithms() {
        assert!(names.insert(entry.name()), "{}", entry.name());
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{}", oid.dotted());
        }
    }
}

#[test]
fn an_unknown_name_or_oid_is_rejected() {
    assert_eq!(name_of("AES512"), Err(SecurityError::UnknownGenerator));
    assert_eq!(name_of(""), Err(SecurityError::UnknownGenerator));
    assert_eq!(name_of("1.2.3.4"), Err(SecurityError::UnknownGenerator));
}

#[cfg(feature = "aes")]
#[test]
fn aes_names_and_aliases_ignore_case() {
    for (name, expected) in [
        ("aes", "AES"),
        ("AESWRAP", "AES"),
        ("aes128", "AES128"),
        ("AES192", "AES192"),
        ("Aes256", "AES256"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn each_aes_oid_finds_the_generator_of_its_key_size() {
    // 2.16.840.1.101.3.4.1 底下：128 bits 是 1 到 8，192 bits 加 20，256 bits 加 40
    for (offset, expected) in [(0, "AES128"), (20, "AES192"), (40, "AES256")] {
        for arc in 1..=8 {
            let dotted = format!("2.16.840.1.101.3.4.1.{}", arc + offset);
            assert_eq!(name_of(&dotted), Ok(expected), "{dotted}");
            assert_eq!(
                generate::get_by_oid(&dotted.parse().unwrap()).map(|entry| entry.name()),
                Ok(expected),
                "{dotted}"
            );
        }
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_is_found_by_name_and_by_rsa_encryption() {
    assert_eq!(name_of("rsa"), Ok("RSA"));
    assert_eq!(name_of("1.2.840.113549.1.1.1"), Ok("RSA"));
}

#[cfg(feature = "aes")]
#[test]
fn aes_takes_only_its_three_key_sizes() {
    use tc_security::generate::KeyGenParams;

    let mut generator = generate::get_by_name("AES").unwrap().generator();
    for strength in [128, 192, 256] {
        assert_eq!(generator.init(&KeyGenParams::Basic { strength }), Ok(()));
    }
    for strength in [0, 32, 100, 512] {
        assert_eq!(
            generator.init(&KeyGenParams::Basic { strength }),
            Err(SecurityError::InvalidKeyGenParams),
            "{strength}"
        );
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_takes_a_modulus_size_alone_or_all_its_parameters() {
    use tc_security::generate::KeyGenParams;

    let mut generator = generate::get_by_name("RSA").unwrap().generator();
    assert_eq!(
        generator.init(&KeyGenParams::Basic { strength: 1024 }),
        Ok(())
    );
    assert_eq!(
        generator.init(&KeyGenParams::Rsa {
            public_exponent: 65537,
            strength: 1024,
            certainty: 100,
        }),
        Ok(())
    );
}

#[cfg(all(feature = "aes", feature = "rsa"))]
#[test]
fn a_generator_rejects_the_parameters_of_another_algorithm() {
    use tc_security::generate::KeyGenParams;

    let mut aes = generate::get_by_name("AES").unwrap().generator();
    assert_eq!(
        aes.init(&KeyGenParams::Rsa {
            public_exponent: 65537,
            strength: 2048,
            certainty: 100,
        }),
        Err(SecurityError::InvalidKeyGenParams)
    );
}

#[cfg(feature = "aes")]
#[test]
fn an_aes_key_is_as_long_as_the_name_or_init_says() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    for (name, bytes) in [("AES", 24), ("AES128", 16), ("AES192", 24), ("AES256", 32)] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        assert_eq!(KeyParams::key(&key).len(), bytes, "{name}");
    }

    let mut generator = generate::get_by_name("AES").unwrap().generator();
    generator
        .init(&KeyGenParams::Basic { strength: 128 })
        .unwrap();
    assert_eq!(KeyParams::key(&generator.generate_key().unwrap()).len(), 16);
}

#[cfg(feature = "aes")]
#[test]
fn keys_come_from_the_given_rng() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_block_cipher::KeyParams;

    let key = |seed| {
        let mut generator = generate::get_by_name("AES256").unwrap().generator();
        generator.with_rng(StdRng::seed_from_u64(seed));
        generator.generate_key().unwrap()
    };
    assert_eq!(KeyParams::key(&key(1)), KeyParams::key(&key(1)));
    assert_ne!(KeyParams::key(&key(1)), KeyParams::key(&key(2)));

    // 預設是作業系統的亂數：每次都不同
    let mut generator = generate::get_by_name("AES256").unwrap().generator();
    let first = generator.generate_key().unwrap();
    let second = generator.generate_key().unwrap();
    assert_ne!(KeyParams::key(&first), KeyParams::key(&second));
}

#[cfg(feature = "aes")]
#[test]
fn a_symmetric_generator_makes_no_key_pair() {
    let mut generator = generate::get_by_name("AES").unwrap().generator();
    let error = generator.generate_key_pair().err().unwrap();
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(
        source.downcast_ref::<SecurityError>(),
        Some(&SecurityError::WrongGenerator)
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_makes_a_public_and_a_private_key_but_no_symmetric_key() {
    use tc_asym_cipher::AsymmetricKeyParams;
    use tc_security::generate::KeyGenParams;
    use tc_security::params::AnyParams;

    let mut generator = generate::get_by_name("RSA").unwrap().generator();
    generator
        .init(&KeyGenParams::Basic { strength: 1024 })
        .unwrap();
    let (public, private) = generator.generate_key_pair().unwrap();
    let (AnyParams::Rsa { key: public }, AnyParams::Rsa { key: private }) = (&public, &private)
    else {
        panic!("RSA generates RSA keys");
    };
    assert!(!public.is_private_key());
    assert!(private.is_private_key());

    assert_eq!(
        generator.generate_key().err(),
        Some(SecurityError::WrongGenerator)
    );
}

#[cfg(feature = "rc2")]
#[test]
fn rc2_keys_default_to_128_bits_and_take_any_length_up_to_1024_bits() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    assert_eq!(name_of("1.2.840.113549.3.2"), Ok("RC2"));
    assert_eq!(name_of("1.2.840.113549.1.9.16.3.7"), Ok("RC2"));

    let mut generator = generate::get_by_name("RC2").unwrap().generator();
    assert_eq!(KeyParams::key(&generator.generate_key().unwrap()).len(), 16);

    generator
        .init(&KeyGenParams::Basic { strength: 40 })
        .unwrap();
    assert_eq!(KeyParams::key(&generator.generate_key().unwrap()).len(), 5);

    for strength in [0, 1025] {
        assert_eq!(
            generator.init(&KeyGenParams::Basic { strength }),
            Err(SecurityError::InvalidKeyGenParams),
            "{strength}"
        );
    }
}

#[cfg(feature = "rc2")]
#[test]
fn rc2_init_can_set_the_effective_key_bits_of_the_key() {
    use tc_block_cipher::KeyParams;
    use tc_rc_cipher::Rc2Params;
    use tc_security::generate::KeyGenParams;
    use tc_security::params::AnyParams;

    let mut generator = generate::get_by_name("RC2").unwrap().generator();
    generator
        .init(&KeyGenParams::Rc2 {
            strength: 128,
            effective_key_bits: 40,
        })
        .unwrap();
    let key = generator.generate_key().unwrap();
    assert!(matches!(key, AnyParams::Rc2 { .. }));
    assert_eq!(KeyParams::key(&key).len(), 16);
    assert_eq!(key.effective_key_bits(), 40);

    for effective_key_bits in [0, 1025] {
        assert_eq!(
            generator.init(&KeyGenParams::Rc2 {
                strength: 128,
                effective_key_bits,
            }),
            Err(SecurityError::InvalidKeyGenParams),
            "{effective_key_bits}"
        );
    }
}

#[cfg(feature = "rc5")]
#[test]
fn rc5_keys_follow_bc_defaults_and_init_can_set_the_rounds() {
    use tc_block_cipher::KeyParams;
    use tc_rc_cipher::Rc5Params;
    use tc_security::generate::KeyGenParams;
    use tc_security::params::AnyParams;

    assert_eq!(name_of("RC5-32"), Ok("RC5"));
    for (name, bytes) in [("RC5", 16), ("RC5-64", 32)] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        assert_eq!(KeyParams::key(&key).len(), bytes, "{name}");
    }

    let mut generator = generate::get_by_name("RC5").unwrap().generator();
    generator
        .init(&KeyGenParams::Rc5 {
            strength: 64,
            rounds: 8,
        })
        .unwrap();
    let key = generator.generate_key().unwrap();
    assert!(matches!(key, AnyParams::Rc5 { .. }));
    assert_eq!(KeyParams::key(&key).len(), 8);
    assert_eq!(key.rounds(), 8);

    for (strength, rounds) in [(0, 12), (2048, 12), (128, 256)] {
        assert_eq!(
            generator.init(&KeyGenParams::Rc5 { strength, rounds }),
            Err(SecurityError::InvalidKeyGenParams),
            "{strength}/{rounds}"
        );
    }
}

#[cfg(feature = "chacha")]
#[test]
fn chacha_keys_follow_the_bc_names_and_sizes() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    for (name, expected) in [
        ("CHACHA20", "CHACHA7539"),
        ("chacha20-poly1305", "CHACHA7539"),
        ("1.2.840.113549.1.9.16.3.18", "CHACHA7539"),
        ("XCHACHA20-POLY1305", "XCHACHA20"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
    for (name, bytes) in [("CHACHA", 16), ("CHACHA7539", 32), ("XCHACHA20", 32)] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        assert_eq!(KeyParams::key(&key).len(), bytes, "{name}");
    }

    let mut chacha = generate::get_by_name("CHACHA").unwrap().generator();
    assert_eq!(chacha.init(&KeyGenParams::Basic { strength: 256 }), Ok(()));
    let mut chacha7539 = generate::get_by_name("CHACHA7539").unwrap().generator();
    assert_eq!(
        chacha7539.init(&KeyGenParams::Basic { strength: 128 }),
        Err(SecurityError::InvalidKeyGenParams)
    );
}

#[cfg(feature = "ascon")]
#[test]
fn ascon_keys_have_the_fixed_size_of_each_variant() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    for (name, bytes) in [
        ("ascon-aead128", 16),
        ("ASCON-128", 16),
        ("ASCON-128A", 16),
        ("ASCON-80PQ", 20),
    ] {
        let mut generator = generate::get_by_name(name).unwrap().generator();
        assert_eq!(
            KeyParams::key(&generator.generate_key().unwrap()).len(),
            bytes,
            "{name}"
        );
        assert_eq!(
            generator.init(&KeyGenParams::Basic { strength: 256 }),
            Err(SecurityError::InvalidKeyGenParams),
            "{name}"
        );
    }
}

#[test]
fn every_generator_makes_its_kind_of_key_and_a_fresh_one_each_time() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    for entry in generate::algorithms() {
        let name = entry.name();
        let mut generator = entry.generator();
        match generator.generate_key() {
            Ok(first) => {
                let second = generator.generate_key().unwrap();
                assert!(!KeyParams::key(&first).is_empty(), "{name}");
                assert_ne!(KeyParams::key(&first), KeyParams::key(&second), "{name}");
                assert!(generator.generate_key_pair().is_err(), "{name}");
            }
            Err(error) => {
                assert_eq!(error, SecurityError::WrongGenerator, "{name}");
                generator
                    .init(&KeyGenParams::Basic { strength: 1024 })
                    .unwrap();
                assert!(generator.generate_key_pair().is_ok(), "{name}");
            }
        }
    }
}

#[cfg(feature = "aes")]
#[test]
fn a_rejected_init_keeps_the_previous_parameters() {
    use tc_block_cipher::KeyParams;
    use tc_security::generate::KeyGenParams;

    let mut generator = generate::get_by_name("AES").unwrap().generator();
    generator
        .init(&KeyGenParams::Basic { strength: 128 })
        .unwrap();
    assert!(
        generator
            .init(&KeyGenParams::Basic { strength: 100 })
            .is_err()
    );
    assert_eq!(KeyParams::key(&generator.generate_key().unwrap()).len(), 16);
}

#[cfg(feature = "aes")]
#[test]
fn a_generated_aes_key_works_with_the_cipher_factory() {
    use tc_block_cipher::KeyParams;
    use tc_security::cipher;
    use tc_security::params::AnyParams;

    let key = generate::get_by_name("AES256")
        .unwrap()
        .generator()
        .generate_key()
        .unwrap();
    let message = b"attack at dawn";

    let cbc = key.clone().with_iv(vec![9; 16]);
    let mut aes = cipher::get_by_name("AES/CBC/PKCS7PADDING")
        .unwrap()
        .cipher();
    let sealed = cipher::encrypt(&mut aes, &cbc, message).unwrap();
    assert_eq!(cipher::decrypt(&mut aes, &cbc, &sealed).unwrap(), message);

    let gcm = AnyParams::aead(KeyParams::key(&key).to_vec(), 128, vec![9; 12], Vec::new());
    let mut aes = cipher::get_by_name("AES/GCM").unwrap().cipher();
    let sealed = cipher::encrypt(&mut aes, &gcm, message).unwrap();
    assert_eq!(cipher::decrypt(&mut aes, &gcm, &sealed).unwrap(), message);
}

#[cfg(feature = "rc2")]
#[test]
fn a_generated_rc2_key_keeps_its_effective_key_bits_in_the_cipher() {
    use tc_block_cipher::KeyParams;
    use tc_security::cipher;
    use tc_security::generate::KeyGenParams;
    use tc_security::params::AnyParams;

    let mut generator = generate::get_by_name("RC2").unwrap().generator();
    generator
        .init(&KeyGenParams::Rc2 {
            strength: 128,
            effective_key_bits: 40,
        })
        .unwrap();
    let key = generator.generate_key().unwrap();
    let bytes = KeyParams::key(&key).to_vec();

    let entry = cipher::get_by_name("RC2/ECB/NOPADDING").unwrap();
    let sealed = cipher::encrypt(&mut entry.cipher(), &key, &[0; 8]).unwrap();
    assert_eq!(
        cipher::encrypt(
            &mut entry.cipher(),
            &AnyParams::rc2(bytes.clone(), 40),
            &[0; 8]
        )
        .unwrap(),
        sealed
    );
    assert_ne!(
        cipher::encrypt(&mut entry.cipher(), &AnyParams::new(bytes), &[0; 8]).unwrap(),
        sealed
    );
}

#[cfg(feature = "rc5")]
#[test]
fn a_generated_rc5_key_keeps_its_rounds_in_the_cipher() {
    use tc_block_cipher::KeyParams;
    use tc_security::cipher;
    use tc_security::generate::KeyGenParams;
    use tc_security::params::AnyParams;

    let mut generator = generate::get_by_name("RC5").unwrap().generator();
    generator
        .init(&KeyGenParams::Rc5 {
            strength: 128,
            rounds: 8,
        })
        .unwrap();
    let key = generator.generate_key().unwrap();
    let bytes = KeyParams::key(&key).to_vec();

    let entry = cipher::get_by_name("RC5/ECB/NOPADDING").unwrap();
    let sealed = cipher::encrypt(&mut entry.cipher(), &key, &[0; 8]).unwrap();
    assert_eq!(
        cipher::encrypt(
            &mut entry.cipher(),
            &AnyParams::rc5(bytes.clone(), 8),
            &[0; 8]
        )
        .unwrap(),
        sealed
    );
    assert_ne!(
        cipher::encrypt(&mut entry.cipher(), &AnyParams::new(bytes), &[0; 8]).unwrap(),
        sealed
    );
}

#[cfg(feature = "chacha")]
#[test]
fn a_generated_chacha_key_works_with_the_cipher_factory() {
    use tc_security::cipher;

    let message = b"attack at dawn";
    for (name, nonce) in [("CHACHA", 8), ("CHACHA7539", 12), ("XCHACHA20", 24)] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        let params = key.with_iv(vec![9; nonce]);
        let mut chacha = cipher::get_by_name(name).unwrap().cipher();
        let sealed = cipher::encrypt(&mut chacha, &params, message).unwrap();
        assert_eq!(
            cipher::decrypt(&mut chacha, &params, &sealed).unwrap(),
            message,
            "{name}"
        );
    }
}

#[cfg(feature = "ascon")]
#[test]
fn a_generated_ascon_key_works_with_the_cipher_factory() {
    use tc_block_cipher::KeyParams;
    use tc_security::cipher;
    use tc_security::params::AnyParams;

    let message = b"attack at dawn";
    for name in ["ASCON-AEAD128", "ASCON-128", "ASCON-128A", "ASCON-80PQ"] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        let params = AnyParams::aead(KeyParams::key(&key).to_vec(), 128, vec![9; 16], Vec::new());
        let mut ascon = cipher::get_by_name(name).unwrap().cipher();
        let sealed = cipher::encrypt(&mut ascon, &params, message).unwrap();
        assert_eq!(
            cipher::decrypt(&mut ascon, &params, &sealed).unwrap(),
            message,
            "{name}"
        );
    }
}

#[cfg(all(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
#[test]
fn cfrg_curves_are_found_by_name_alias_and_rfc_8410_oid() {
    for (name, expected) in [
        ("x25519", "X25519"),
        ("1.3.101.110", "X25519"),
        ("x448", "X448"),
        ("1.3.101.111", "X448"),
        ("ed25519ctx", "Ed25519"),
        ("Ed25519ph", "Ed25519"),
        ("1.3.101.112", "Ed25519"),
        ("ED448PH", "Ed448"),
        ("1.3.101.113", "Ed448"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
}

#[cfg(all(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
#[test]
fn each_cfrg_curve_makes_a_key_pair_whose_public_key_comes_from_the_private_key() {
    use tc_security::params::AnyParams;

    for name in ["X25519", "X448", "Ed25519", "Ed448"] {
        let mut generator = generate::get_by_name(name).unwrap().generator();
        let (public, private) = generator.generate_key_pair().unwrap();
        let derived = match (&public, &private) {
            (
                AnyParams::X25519Public { key: public },
                AnyParams::X25519Private { key: private },
            ) => *public == private.generate_public_key(),
            (AnyParams::X448Public { key: public }, AnyParams::X448Private { key: private }) => {
                *public == private.generate_public_key()
            }
            (
                AnyParams::Ed25519Public { key: public },
                AnyParams::Ed25519Private { key: private },
            ) => *public == private.generate_public_key(),
            (AnyParams::Ed448Public { key: public }, AnyParams::Ed448Private { key: private }) => {
                *public == private.generate_public_key()
            }
            _ => false,
        };
        assert!(derived, "{name}");
        assert_eq!(
            generator.generate_key().err(),
            Some(SecurityError::WrongGenerator),
            "{name}"
        );
    }
}

#[cfg(all(feature = "x25519", feature = "rsa"))]
#[test]
fn a_cfrg_curve_ignores_the_strength_but_rejects_other_parameters() {
    use tc_security::generate::KeyGenParams;

    let mut generator = generate::get_by_name("X25519").unwrap().generator();
    assert_eq!(generator.init(&KeyGenParams::Basic { strength: 1 }), Ok(()));
    assert_eq!(
        generator.init(&KeyGenParams::Rsa {
            public_exponent: 65537,
            strength: 2048,
            certainty: 100,
        }),
        Err(SecurityError::InvalidKeyGenParams)
    );
}

#[cfg(feature = "x25519")]
#[test]
fn cfrg_key_pairs_come_from_the_given_rng() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_security::params::AnyParams;

    let public = |seed| {
        let mut generator = generate::get_by_name("X25519").unwrap().generator();
        generator.with_rng(StdRng::seed_from_u64(seed));
        let (public, _) = generator.generate_key_pair().unwrap();
        let AnyParams::X25519Public { key } = &public else {
            panic!("X25519 generates X25519 keys");
        };
        key.clone()
    };
    assert_eq!(public(1), public(1));
    assert_ne!(public(1), public(2));
}
