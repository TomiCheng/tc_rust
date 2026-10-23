use tc_pbe::{
    PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs12, pkcs12_password_to_bytes,
};
use tc_sha::Sha1Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn generator(password: &str, salt: &str, count: usize) -> Pkcs12<Sha1Digest> {
    let password = pkcs12_password_to_bytes(password, false);
    let mut generator = Pkcs12::new(Sha1Digest::new());
    generator
        .init(&PbeParamsRef::new(&password, &hex(salt), count))
        .unwrap();
    generator
}

/// BC Pkcs12Test 的 Run1：DESede 的 24 bytes 金鑰，跨兩個 SHA-1 區塊。
fn key(password: &str, salt: &str, count: usize) -> Vec<u8> {
    let mut key = vec![0; 24];
    generator(password, salt, count)
        .derive_key(&mut key)
        .unwrap();
    key
}

/// BC Pkcs12Test 的 Run2：DES 金鑰之外的 8 bytes IV。
fn iv(password: &str, salt: &str, count: usize) -> Vec<u8> {
    let (mut key, mut iv) = ([0; 8], vec![0; 8]);
    generator(password, salt, count)
        .derive_key_and_iv(&mut key, &mut iv)
        .unwrap();
    iv
}

/// BC Pkcs12Test 的 Run3：160 bits 的 MAC 金鑰。
fn mac_key(password: &str, salt: &str, count: usize) -> Vec<u8> {
    let mut key = vec![0; 20];
    generator(password, salt, count)
        .derive_mac_key(&mut key)
        .unwrap();
    key
}

#[test]
fn keys_ivs_and_mac_keys_match_bcs_pkcs12_test() {
    assert_eq!(
        key("smeg", "0A58CF64530D823F", 1),
        hex("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3")
    );
    assert_eq!(iv("smeg", "0A58CF64530D823F", 1), hex("79993DFE048D3B76"));
    assert_eq!(
        key("smeg", "642B99AB44FB4B1F", 1),
        hex("F3A95FEC48D7711E985CFE67908C5AB79FA3D7C5CAA5D966")
    );
    assert_eq!(iv("smeg", "642B99AB44FB4B1F", 1), hex("C0A38D64A79BEA1D"));
    assert_eq!(
        mac_key("smeg", "3D83C0E4546AC140", 1),
        hex("8D967D88F6CAA9D714800AB3D48051D63F73A312")
    );
    assert_eq!(
        key("queeg", "05DEC959ACFF72F7", 1000),
        hex("ED2034E36328830FF09DF1E1A07DD357185DAC0D4F9EB3D4")
    );
    assert_eq!(
        iv("queeg", "05DEC959ACFF72F7", 1000),
        hex("11DEDAD7758D4860")
    );
    assert_eq!(
        key("queeg", "1682C0FC5B3F7EC5", 1000),
        hex("483DD6E919D7DE2E8E648BA8F862F3FBFBDC2BCB2C02957F")
    );
    assert_eq!(
        iv("queeg", "1682C0FC5B3F7EC5", 1000),
        hex("9D461D1B00355C50")
    );
    assert_eq!(
        mac_key("queeg", "263216FCC2FAB31C", 1000),
        hex("5EC4C7A80DF652294C3925B6489A7AB857C83476")
    );
}

#[test]
fn the_three_id_bytes_give_three_different_outputs() {
    let mut generator = generator("smeg", "0A58CF64530D823F", 1);
    let (mut key, mut iv, mut mac_key) = ([0; 20], [0; 20], [0; 20]);
    generator.derive_key_and_iv(&mut key, &mut iv).unwrap();
    generator.derive_mac_key(&mut mac_key).unwrap();
    assert_ne!(key, iv);
    assert_ne!(key, mac_key);
    assert_ne!(iv, mac_key);
}

#[test]
fn a_zero_iteration_count_is_refused_and_init_comes_first() {
    let mut generator = Pkcs12::new(Sha1Digest::new());
    assert_eq!(
        generator.derive_key(&mut [0; 8]),
        Err(PbeError::NotInitialised)
    );
    assert_eq!(
        generator.init(&PbeParamsRef::new(b"pw", b"salt", 0)),
        Err(PbeError::InvalidIterationCount(0))
    );
}
