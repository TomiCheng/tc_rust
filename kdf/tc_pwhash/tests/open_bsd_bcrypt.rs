//! Bouncy Castle's `OpenBsdBCryptTest` vectors, and reading malformed hash strings.

#![cfg(feature = "bcrypt")]

use tc_pwhash::bcrypt::{BcryptError, BcryptVersion, OpenBsdBcrypt};

fn check(hash: &str, password: &str) -> bool {
    OpenBsdBcrypt::check_password(hash, password.as_bytes()).unwrap()
}

#[test]
fn bc_vectors_check_against_their_passwords() {
    for (hash, password) in [
        (
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            "U*U",
        ),
        (
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
            "U*U*",
        ),
        (
            "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
            "U*U*U",
        ),
        (
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
            "",
        ),
        (
            "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe",
            "password",
        ),
        (
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe",
            "a",
        ),
        (
            "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i",
            "abc",
        ),
        (
            "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO",
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        ),
        (
            "$2a$04$yRZW9xEsqN9DL19jveqFyO1bljZ0r5KNCYqQzMqYpDB7XHWqDWNGC",
            "O9X[kP6{63F\u{7f}3rXKtN>n?zh2_",
        ),
        (
            "$2a$04$KhDTFUlakUsPNuLQSgyr7.xQZxkTSIvo0nFw0XyjvrH6n5kZkYDLG",
            ":Sa:Bkne\u{7f}psG}\\5dOj>kh0KAk",
        ),
        (
            "$2a$04$xUNE1aUuNlpNwSOuz1VpjuBgW95ImLccIquQxyGLeinucvokg2Ale",
            "2KNy`Kodau14?s8XVru<IIw0eDw|.64MM^Wtv;3sfZt~3`2QN6/U]0\u{7f}^1HtETqWHt<lMfD-LX::zo7AcNLQ.Q.@.g5kX`j7hRi",
        ),
    ] {
        assert!(check(hash, password), "{hash}");
    }
}

#[test]
fn bytes_past_the_72nd_are_ignored() {
    let hash = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui";
    let password = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    assert!(check(hash, password));
    assert!(check(
        hash,
        &format!("{password}chars after 72 are ignored")
    ));
    assert!(!check(hash, &password[..71]));
}

#[test]
fn non_ascii_passwords_are_hashed_as_utf8() {
    assert!(check(
        "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle",
        "ππππππππ"
    ));
}

#[test]
fn generating_with_the_salt_of_a_bc_vector_reproduces_its_string() {
    for (password, salt, cost, expected) in [
        (
            "",
            "DCq7YPn5Rq63x1Lad4cll.",
            6,
            "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.",
        ),
        (
            "a",
            "m0CrhHm10qJ3lXRY.5zDGO",
            6,
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe",
        ),
        (
            "abc",
            "Ro0CUfOqk6cXEKf3dyaM7O",
            8,
            "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            ".rCVZVOThsIa97pEDOxvGu",
            6,
            "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC",
        ),
    ] {
        assert_eq!(
            OpenBsdBcrypt::generate_with_version(
                BcryptVersion::V2a,
                password.as_bytes(),
                &decode_salt(salt),
                cost
            )
            .unwrap(),
            expected
        );
    }
}

fn decode_salt(text: &str) -> [u8; 16] {
    const ALPHABET: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        bits = bits << 6 | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out.try_into().unwrap()
}

#[test]
fn the_2y_and_2b_labels_hash_alike_and_2y_is_the_default() {
    let hash_2y = "$2y$12$DB3BUbYa/SsEL7kCOVji0OauTkPkB5Y1OeyfxJHM7jvMrbml5sgD2";
    assert!(check(hash_2y, "a"));
    assert!(check(&hash_2y.replacen("2y", "2b", 1), "a"));
    assert!(!check(hash_2y, "b"));

    let salt = [7; 16];
    let default = OpenBsdBcrypt::generate(b"a", &salt, 4).unwrap();
    assert!(default.starts_with("$2y$04$"));
    let labelled =
        OpenBsdBcrypt::generate_with_version(BcryptVersion::V2b, b"a", &salt, 4).unwrap();
    assert_eq!(labelled[7..], default[7..]);
}

#[test]
fn malformed_strings_unsupported_versions_and_bad_costs_are_errors() {
    let good = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    let read = |hash: &str| OpenBsdBcrypt::check_password(hash, b"U*U");

    assert_eq!(read(&good[..59]), Err(BcryptError::MalformedHash));
    assert_eq!(
        read(&good.replacen('$', "#", 1)),
        Err(BcryptError::MalformedHash)
    );
    assert_eq!(
        read(&good.replacen("$05$", "$5$$", 1)),
        Err(BcryptError::MalformedHash)
    );
    assert_eq!(
        read(&good.replacen("$05$", "$+5$", 1)),
        Err(BcryptError::MalformedHash)
    );
    assert_eq!(
        read(&good.replacen("CCCC", "CC_C", 1)),
        Err(BcryptError::MalformedHash)
    );
    assert_eq!(
        read(&good.replacen("2a", "2x", 1)),
        Err(BcryptError::UnsupportedVersion)
    );
    assert_eq!(
        read(&good.replacen("$05$", "$03$", 1)),
        Err(BcryptError::InvalidCost(3))
    );
    assert_eq!(
        read(&good.replacen("$05$", "$32$", 1)),
        Err(BcryptError::InvalidCost(32))
    );

    let wrong_hash = good.replacen("Kvy", "Kvz", 1);
    assert_eq!(read(&wrong_hash), Ok(false));
    assert_eq!(read(good), Ok(true));
    assert_eq!(
        OpenBsdBcrypt::generate(b"a", &[0; 16], 3),
        Err(BcryptError::InvalidCost(3))
    );
}
