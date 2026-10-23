//! cipher 工廠的 Salsa20、RC4、VMPC 與 HC：已知答案、名稱與 OID，以及產生的金鑰長度。

#![cfg(any(feature = "salsa20", feature = "rc4", feature = "vmpc", feature = "hc"))]

use tc_security::params::AnyParams;
use tc_security::{cipher, generate};

#[allow(dead_code, reason = "只開了 vmpc 時用不到")]
fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// 用工廠的 cipher 加密 `length` bytes 的零，也就是 keystream。
#[allow(dead_code, reason = "只開了 rc4 時用不到")]
fn keystream(name: &str, params: &AnyParams, length: usize) -> Vec<u8> {
    let mut cipher = cipher::get_by_name(name).unwrap().cipher();
    cipher::encrypt(&mut cipher, params, &vec![0; length]).unwrap()
}

/// 產生器的預設金鑰長度（bytes）。
fn default_key_bytes(name: &str) -> usize {
    let mut generator = generate::get_by_name(name).unwrap().generator();
    match generator.generate_key().unwrap() {
        AnyParams::Key { ref key } => key.len(),
        _ => panic!("{name}: a plain key"),
    }
}

#[cfg(feature = "salsa20")]
#[test]
fn salsa20_matches_bc_with_a_128_bit_key() {
    let params = AnyParams::new(hex("80000000000000000000000000000000")).with_iv(vec![0; 8]);
    assert_eq!(
        keystream("SALSA20", &params, 64),
        hex(
            "4DFA5E481DA23EA09A31022050859936 DA52FCEE218005164F267CB65F5CFD7F
             2B4F97E0FF16924A52DF269515110A07 F9E460BC65EF95DA58F740B7D1DBB0AA"
        )
    );
    assert_eq!(default_key_bytes("SALSA20"), 16);
}

#[cfg(feature = "rc4")]
#[test]
fn arc4_matches_the_classic_vector_under_every_bc_name_and_its_oid() {
    let params = AnyParams::new(b"Key".to_vec());
    for name in ["ARC4", "RC4", "arcfour", "1.2.840.113549.3.4"] {
        assert_eq!(cipher::get_by_name(name).unwrap().name(), "ARC4", "{name}");
        let mut cipher = cipher::get_by_name(name).unwrap().cipher();
        assert_eq!(
            cipher::encrypt(&mut cipher, &params, b"Plaintext").unwrap(),
            hex("BBF316E8D940AF0AD3"),
            "{name}"
        );
    }
    assert_eq!(default_key_bytes("RC4"), 16);
}

/// VMPC 的已知答案在 tc_rc4_family 裡；這裡確認工廠用的就是那兩個引擎。
#[cfg(feature = "vmpc")]
#[test]
fn vmpc_and_vmpc_ksa3_are_the_tc_rc4_family_engines() {
    use tc_rc4_family::{VmpcEngine, VmpcKsa3Engine};
    use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

    let (key, iv) = ([0x11; 16], [0x22; 20]);
    let params = AnyParams::new(key.to_vec()).with_iv(iv.to_vec());

    let mut engine = VmpcEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
        .unwrap();
    let mut expected = vec![0; 100];
    engine.process_bytes(&[0; 100], &mut expected).unwrap();
    assert_eq!(keystream("VMPC", &params, 100), expected);

    let mut engine = VmpcKsa3Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
        .unwrap();
    engine.process_bytes(&[0; 100], &mut expected).unwrap();
    assert_eq!(keystream("VMPC-KSA3", &params, 100), expected);
    assert_eq!(
        cipher::get_by_name("VMPC_KSA3").unwrap().name(),
        "VMPC-KSA3"
    );
    assert_eq!(default_key_bytes("VMPC"), 16);
}

#[cfg(feature = "hc")]
#[test]
fn hc128_and_hc256_match_their_official_vectors() {
    let params = AnyParams::new(vec![0; 16]).with_iv(vec![0; 16]);
    assert_eq!(
        keystream("HC128", &params, 16),
        hex("82001573A003FD3B7FD72FFB0EAF63AA")
    );
    assert_eq!(
        keystream("HC256", &params, 16),
        hex("5B078985D8F6F30D42C5C02FA6B67951")
    );
    assert_eq!(default_key_bytes("HC128"), 16);
    assert_eq!(default_key_bytes("HC256"), 32);
}
