//! Bouncy Castle's `BCryptTest` vectors for the raw function, and its limits.

#![cfg(feature = "bcrypt")]

use tc_pwhash::bcrypt::{Bcrypt, BcryptError};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn salt(text: &str) -> [u8; 16] {
    hex(text).try_into().unwrap()
}

#[test]
fn bc_vectors_with_terminated_passwords_give_their_hashes() {
    for (password, salt_hex, cost, expected) in [
        (
            "",
            "144b3d691a7b4ecf39cf735c7fa7a79c",
            6,
            "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092",
        ),
        (
            "00",
            "144b3d691a7b4ecf39cf735c7fa7a79c",
            6,
            "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092",
        ),
        (
            "00",
            "26c63033c04f8bcba2fe24b574db6274",
            8,
            "56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48ba",
        ),
        (
            "6100",
            "a3612d8c9a37dac2f99d94da03bd4521",
            6,
            "e6d53831f82060dc08a2e8489ce850ce48fbf976978738f3",
        ),
        (
            "6100",
            "7a17b15dfe1c4be10ec6a3ab47818386",
            8,
            "a9f3469a61cbff0a0f1a1445dfe023587f38b2c9c40570e1",
        ),
        (
            "61626300",
            "2a1f1dc70a3d147956a46febe3016017",
            6,
            "d9a275b493bcbe1024b0ff80d330253cfdca34687d8f69e5",
        ),
        (
            "61626300",
            "4ead845a142c9bc79918c8797f470ef5",
            8,
            "8d4131a723bfbbac8a67f2e035cae08cc33b69f37331ea91",
        ),
        (
            "6162636465666768696a6b6c6d6e6f707172737475767778797a00",
            "02d1176d74158ee29cffdac6150cf123",
            6,
            "4d38b523ce9dc6f2f6ff9fb3c2cd71dfe7f96eb4a3baf19f",
        ),
        (
            "7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400",
            "8512ae0d0fac4ec9a5978f79b6171028",
            6,
            "26f517fe5345ad575ba7dfb8144f01bfdb15f3d47c1e146a",
        ),
        (
            "c2a300",
            "144b3d691a7b4ecf39cf735c7fa7a79c",
            6,
            "5a6c4fedb23980a7da9217e0442565ac6145b687c7313339",
        ),
    ] {
        assert_eq!(
            Bcrypt::generate(&hex(password), &salt(salt_hex), cost, false)
                .unwrap()
                .to_vec(),
            hex(expected),
            "{password} / {cost}"
        );
    }
}

#[test]
fn bc_vectors_from_utf8_passwords_with_the_terminator_added() {
    let salt = salt("01020304050607080102030405060708");
    assert_eq!(
        Bcrypt::generate(b"12341234", &salt, 5, true)
            .unwrap()
            .to_vec(),
        hex("cdd19088721c50e5cb49a7b743d93b5a6e67bef0f700cd78")
    );
    assert_eq!(
        Bcrypt::generate(b"1234", &salt, 5, true).unwrap().to_vec(),
        hex("02a3269aca2732484057b40c614204814cbfc2becd8e093e")
    );
}

#[test]
fn an_empty_password_hashes_as_four_zero_bytes_and_short_keys_are_not_padded() {
    let salt = [0; 16];
    let empty = Bcrypt::generate(&[], &salt, 4, false).unwrap();
    assert_eq!(empty, Bcrypt::generate(&[0], &salt, 4, false).unwrap());
    assert_eq!(empty, Bcrypt::generate(&[0; 4], &salt, 4, false).unwrap());
    assert_ne!(
        Bcrypt::generate(b"a", &salt, 4, false).unwrap(),
        Bcrypt::generate(b"a\0", &salt, 4, false).unwrap()
    );
}

#[test]
fn adding_the_terminator_matches_the_terminated_vector_and_is_ignored_at_72_bytes() {
    let salt = salt("a3612d8c9a37dac2f99d94da03bd4521");
    let expected = hex("e6d53831f82060dc08a2e8489ce850ce48fbf976978738f3");
    assert_eq!(
        Bcrypt::generate(b"a", &salt, 6, true).unwrap().to_vec(),
        expected
    );
    assert_ne!(
        Bcrypt::generate(b"a", &salt, 6, false).unwrap().to_vec(),
        expected
    );

    let full = [b'x'; 72];
    assert_eq!(
        Bcrypt::generate(&full, &salt, 4, true),
        Bcrypt::generate(&full, &salt, 4, false)
    );
}

#[test]
fn passwords_over_72_bytes_and_costs_outside_4_to_31_are_rejected() {
    let salt = [0; 16];
    assert!(Bcrypt::generate(&[0; 72], &salt, 4, true).is_ok());
    assert_eq!(
        Bcrypt::generate(&[0; 73], &salt, 4, false),
        Err(BcryptError::PasswordTooLong(73))
    );
    assert_eq!(
        Bcrypt::generate(&[0; 73], &salt, 4, true),
        Err(BcryptError::PasswordTooLong(73))
    );
    assert_eq!(
        Bcrypt::generate(&[0; 16], &salt, 3, false),
        Err(BcryptError::InvalidCost(3))
    );
    assert_eq!(
        Bcrypt::generate(&[0; 16], &salt, 32, false),
        Err(BcryptError::InvalidCost(32))
    );
}
