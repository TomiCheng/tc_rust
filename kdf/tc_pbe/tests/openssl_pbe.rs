//! 期望值由 OpenSSL 3.5 的 `openssl enc -<cipher> -pass pass:<密碼> -S 0001020304050607 -md <digest> -P`
//! 印出，也以 Python 照 `EVP_BytesToKey` 另外算過。

use tc_digest::Digest;
use tc_md::Md5Digest;
use tc_pbe::{
    OpenSslPbe, PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, pkcs5_password_to_bytes,
};
use tc_sha::Sha256Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const SALT: &str = "0001020304050607";

fn key_and_iv<D: Digest>(
    digest: D,
    password: &str,
    key_len: usize,
    iv_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let password = pkcs5_password_to_bytes(password);
    let mut generator = OpenSslPbe::new(digest);
    generator
        .init(&PbeParamsRef::new(&password, &hex(SALT), 1))
        .unwrap();
    let (mut key, mut iv) = (vec![0; key_len], vec![0; iv_len]);
    generator.derive_key_and_iv(&mut key, &mut iv).unwrap();
    (key, iv)
}

#[test]
fn aes_256_cbc_over_md5_matches_openssl_enc_across_three_md5_blocks() {
    let (key, iv) = key_and_iv(Md5Digest::new(), "password", 32, 16);
    assert_eq!(
        key,
        hex("B03096345E805D3AA4392D2E72791DFB13E12D3F61094A3FC347ACE86B99ADA6")
    );
    assert_eq!(iv, hex("ACDE38B46073EEF81840283E44A4B22A"));
}

#[test]
fn aes_256_cbc_over_sha256_matches_openssl_enc() {
    let (key, iv) = key_and_iv(Sha256Digest::new(), "password", 32, 16);
    assert_eq!(
        key,
        hex("AB47A551C847884819019C30E7B50CB3A26DF8BE39FBBF3943C61C5547FC55F7")
    );
    assert_eq!(iv, hex("1E35F6A0C990BDC44E77B8AC2CFB14D0"));
}

#[test]
fn bcs_openssl_pbe_password_for_aes_128_matches_openssl_enc() {
    let (key, iv) = key_and_iv(
        Md5Digest::new(),
        "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
        16,
        16,
    );
    assert_eq!(key, hex("65801049C51D116008B04C2972AE409F"));
    assert_eq!(iv, hex("B2FF3D10E2ED629D23EF7081C39FBDE6"));
}

#[test]
fn the_iteration_count_is_ignored_as_in_bc() {
    let password = pkcs5_password_to_bytes("password");
    let salt = hex(SALT);
    let derive = |count| {
        let mut generator = OpenSslPbe::new(Md5Digest::new());
        generator
            .init(&PbeParamsRef::new(&password, &salt, count))
            .unwrap();
        let mut key = [0; 32];
        generator.derive_key(&mut key).unwrap();
        key
    };
    assert_eq!(derive(0), derive(1));
    assert_eq!(derive(1000), derive(1));
}

#[test]
fn generating_before_init_fails() {
    let mut generator = OpenSslPbe::new(Md5Digest::new());
    assert_eq!(
        generator.derive_key(&mut [0; 16]),
        Err(PbeError::NotInitialised)
    );
}
