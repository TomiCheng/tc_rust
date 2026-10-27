//! The RFC 7914 vectors Bouncy Castle's `SCryptTest` runs, and its parameter limits.

use tc_pwhash::scrypt::{Scrypt, ScryptError};

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn derive(password: &str, salt: &str, n: u32, r: u32, p: u32) -> Vec<u8> {
    let mut key = vec![0; 64];
    Scrypt::generate(password.as_bytes(), salt.as_bytes(), n, r, p, &mut key).unwrap();
    key
}

#[test]
fn rfc_vectors_up_to_n_16384_derive_their_keys() {
    assert_eq!(
        derive("", "", 16, 1, 1),
        hex("77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
             f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
             fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
             e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06")
    );
    assert_eq!(
        derive("password", "NaCl", 1024, 8, 16),
        hex("fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
             7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
             2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
             c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40")
    );
    assert_eq!(
        derive("pleaseletmein", "SodiumChloride", 16384, 8, 1),
        hex("70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
             fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
             d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
             e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87")
    );
}

#[test]
#[ignore = "needs 1 GiB and minutes in debug; BC skips it too"]
fn the_rfc_vector_with_n_2_to_the_20_derives_its_key() {
    assert_eq!(
        derive("pleaseletmein", "SodiumChloride", 1 << 20, 8, 1),
        hex("21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
             ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
             8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
             37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4")
    );
}

#[test]
fn a_shorter_key_is_a_prefix_of_a_longer_one() {
    let long = derive("password", "NaCl", 16, 1, 1);
    let mut short = [0; 20];
    Scrypt::generate(b"password", b"NaCl", 16, 1, 1, &mut short).unwrap();
    assert_eq!(short, long[..20]);
}

#[test]
fn bc_parameter_limits_are_kept() {
    let run = |n, r, p, len| Scrypt::generate(&[], &[], n, r, p, &mut vec![0; len]);

    assert_eq!(run(2, 1, 1, 1), Ok(()));
    assert_eq!(run(1, 1, 1, 1), Err(ScryptError::InvalidCost(1)));
    assert_eq!(run(6, 2, 1, 1), Err(ScryptError::InvalidCost(6)));
    assert_eq!(run(32768, 1, 1, 1), Ok(()));
    assert_eq!(run(65536, 1, 1, 1), Err(ScryptError::InvalidCost(65536)));
    assert_eq!(run(2, 0, 2, 1), Err(ScryptError::InvalidBlockSize(0)));
    assert_eq!(run(2, 1, 0, 1), Err(ScryptError::InvalidParallelism(0)));
    assert_eq!(
        run(2, 32, 65536, 1),
        Err(ScryptError::InvalidParallelism(65536))
    );
    assert_eq!(run(2, 1, 1, 0), Err(ScryptError::EmptyOutput));
}

#[test]
fn a_table_too_large_to_allocate_is_an_error_rather_than_an_abort() {
    let mut key = [0; 32];
    assert_eq!(
        Scrypt::generate(b"password", b"NaCl", 1 << 31, 1 << 20, 1, &mut key),
        Err(ScryptError::OutOfMemory)
    );
}
