// The block ciphers of the table besides AES and DES, which have files of their own: a known
// answer for each, from the tests of its crate, then what holds for all of them
#![cfg(any(
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast5",
    feature = "cast6",
    feature = "desede",
    feature = "gost28147",
    feature = "idea",
    feature = "noekeon",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "rijndael",
    feature = "seed",
    feature = "serpent",
    feature = "skipjack",
    feature = "sm4",
    feature = "tea",
    feature = "threefish",
    feature = "tnepres",
    feature = "twofish",
    feature = "xtea"
))]

use std::sync::LazyLock;

use tc_algo_old::{Algo, AnyKeyParams, AnyParams, CipherEntry, SecretKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn params(key: &[u8], iv: Option<&[u8]>) -> AnyParams {
    let mut params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(key.to_vec())));
    params.op.iv = iv.map(<[u8]>::to_vec);
    params
}

// Encrypts in ECB without padding, where the output is the engine's alone, and decrypts back
#[allow(dead_code, reason = "each known answer has its own feature")]
fn assert_ecb(algorithm: &str, key: &str, plaintext: &str, ciphertext: &str) {
    let name = format!("{algorithm}/ECB/NOPADDING");
    let params = params(&hex(key), None);
    let output = ALGO
        .cipher()
        .encrypt(&name, &params, &hex(plaintext))
        .unwrap();
    assert_eq!(output, hex(ciphertext), "{name}");
    assert_eq!(
        ALGO.cipher().decrypt(&name, &params, &output).unwrap(),
        hex(plaintext),
        "{name}"
    );
}

#[cfg(feature = "aria")]
#[test]
fn aria_gives_the_rfc_5794_ciphertext() {
    assert_ecb(
        "ARIA",
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "d718fbd6ab644c739da95f3be6451778",
    );
}

#[cfg(feature = "blowfish")]
#[test]
fn blowfish_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "BLOWFISH",
        "0123456789ABCDEF",
        "1111111111111111",
        "61F9C3802281B096",
    );
}

#[cfg(feature = "camellia")]
#[test]
fn camellia_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "CAMELLIA",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "07923A39EB0A817D1C4D87BDB82D1F1C",
    );
}

#[cfg(feature = "cast5")]
#[test]
fn cast5_gives_the_rfc_2144_ciphertext() {
    assert_ecb(
        "CAST5",
        "0123456712345678234567893456789A",
        "0123456789ABCDEF",
        "238B4FE5847E44B2",
    );
}

#[cfg(feature = "cast6")]
#[test]
fn cast6_gives_the_rfc_2612_ciphertext() {
    assert_ecb(
        "CAST6",
        "2342bb9efa38542c0af75647f29f615d",
        "00000000000000000000000000000000",
        "c842a08972b43d20836c91d1b7530f6b",
    );
}

#[cfg(feature = "desede")]
#[test]
fn desede_gives_the_two_key_triple_des_ciphertext() {
    assert_ecb(
        "DESEDE",
        "0123456789abcdeffedcba9876543210",
        "4e6f77206973207468652074696d6520666f7220616c6c20",
        "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c",
    );
}

#[cfg(feature = "gost28147")]
#[test]
fn gost28147_with_the_default_s_box_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "GOST28147",
        "546d203368656c326973652073736e62206167796967747473656865202c3d73",
        "0000000000000000",
        "1b0bbc32cebcab42",
    );
}

#[cfg(feature = "idea")]
#[test]
fn idea_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "IDEA",
        "00112233445566778899AABBCCDDEEFF",
        "000102030405060708090a0b0c0d0e0f",
        "ed732271a7b39f475b4b2b6719f194bf",
    );
}

#[cfg(feature = "noekeon")]
#[test]
fn noekeon_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "NOEKEON",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "b1656851699e29fa24b70148503d2dfc",
    );
}

#[cfg(feature = "rc2")]
#[test]
fn rc2_takes_as_many_effective_bits_as_the_key_has() {
    // An eight-byte key with 64 effective bits
    assert_ecb(
        "RC2",
        "ffffffffffffffff",
        "ffffffffffffffff",
        "278b27e42e2f0d49",
    );
}

#[cfg(feature = "rc5")]
#[test]
fn rc5_runs_twelve_rounds() {
    assert_ecb(
        "RC5",
        "0102030405060708",
        "ffffffffffffffff",
        "e493f1c1bb4d6e8c",
    );
}

#[cfg(feature = "rc5-64")]
#[test]
fn rc5_64_runs_twelve_rounds() {
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
    let (key, plaintext) = ([7; 16], [9; 16]);
    let mut engine = tc_rc_cipher::Rc564Engine::new();
    let rc5 = tc_rc_cipher::Rc5ParamsRef::new(&key, 12);
    engine.init(CipherDirection::Encrypt, &rc5).unwrap();
    let mut expected = [0; 16];
    engine.process_block(&plaintext, &mut expected).unwrap();
    let output = ALGO
        .cipher()
        .encrypt("RC5-64/ECB/NOPADDING", &params(&key, None), &plaintext)
        .unwrap();
    assert_eq!(output, expected);
}

#[cfg(feature = "rc6")]
#[test]
fn rc6_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "RC6",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "f71f65e7b80c0c6966fee607984b5cdf",
    );
}

#[cfg(feature = "rijndael")]
#[test]
fn rijndael_of_128_bit_blocks_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "RIJNDAEL",
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0edd33d3c621e546455bd8ba1418bec8",
    );
}

#[cfg(feature = "seed")]
#[test]
fn seed_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "SEED",
        "00000000000000000000000000000000",
        "000102030405060708090a0b0c0d0e0f",
        "5EBAC6E0054E166819AFF1CC6D346CDB",
    );
}

#[cfg(feature = "serpent")]
#[test]
fn serpent_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "SERPENT",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "3620b17ae6a993d09618b8768266bae9",
    );
}

#[cfg(feature = "skipjack")]
#[test]
fn skipjack_gives_the_known_ciphertext() {
    assert_ecb(
        "SKIPJACK",
        "00998877665544332211",
        "33221100ddccbbaa",
        "2587cae27a12d300",
    );
}

#[cfg(feature = "sm4")]
#[test]
fn sm4_gives_the_gb_t_32907_ciphertext() {
    assert_ecb(
        "SM4",
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246",
    );
}

#[cfg(feature = "tea")]
#[test]
fn tea_gives_the_known_ciphertext() {
    assert_ecb(
        "TEA",
        "0123456712345678234567893456789A",
        "0102030405060708",
        "773dc179878a81c0",
    );
}

#[cfg(feature = "threefish")]
#[test]
fn threefish_with_a_zero_tweak_gives_the_skein_ciphertexts() {
    assert_ecb(
        "THREEFISH-256",
        &"00".repeat(32),
        &"00".repeat(32),
        "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8",
    );
    assert_ecb(
        "THREEFISH-512",
        &"00".repeat(64),
        &"00".repeat(64),
        "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b\
         7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe",
    );
    assert_ecb(
        "THREEFISH-1024",
        &"00".repeat(128),
        &"00".repeat(128),
        "f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90d\
         f0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a2\
         0b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa\
         9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e",
    );
}

#[cfg(feature = "tnepres")]
#[test]
fn tnepres_gives_the_bouncy_castle_ciphertext() {
    assert_ecb(
        "TNEPRES",
        &"00".repeat(32),
        "00000000000000000000000000000000",
        "8910494504181950f98dd998a82b6749",
    );
}

#[cfg(feature = "twofish")]
#[test]
fn twofish_gives_the_known_ciphertext() {
    assert_ecb(
        "TWOFISH",
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
        "9fb63337151be9c71306d159ea7afaa4",
    );
}

#[cfg(feature = "xtea")]
#[test]
fn xtea_gives_the_known_ciphertext() {
    assert_ecb(
        "XTEA",
        "00000000000000000000000000000000",
        "0102030405060708",
        "065c1b8975c6a816",
    );
}

// A key length each takes, and its block size
const SIZES: &[(&str, usize, usize)] = &[
    ("ARIA", 16, 16),
    ("BLOWFISH", 16, 8),
    ("CAMELLIA", 16, 16),
    ("CAST5", 16, 8),
    ("CAST6", 16, 16),
    ("DESEDE", 24, 8),
    ("GOST28147", 32, 8),
    ("IDEA", 16, 8),
    ("NOEKEON", 16, 16),
    ("RC2", 16, 8),
    ("RC5", 16, 8),
    ("RC5-64", 16, 16),
    ("RC6", 16, 16),
    ("RIJNDAEL", 16, 16),
    ("SEED", 16, 16),
    ("SERPENT", 16, 16),
    ("SKIPJACK", 10, 8),
    ("SM4", 16, 16),
    ("TEA", 16, 8),
    ("THREEFISH-256", 32, 32),
    ("THREEFISH-512", 64, 64),
    ("THREEFISH-1024", 128, 128),
    ("TNEPRES", 16, 16),
    ("TWOFISH", 16, 16),
    ("XTEA", 16, 8),
];

fn entries_of(algorithm: &str) -> impl Iterator<Item = &'static CipherEntry> + '_ {
    ALGO.cipher()
        .algorithms()
        .filter(move |entry| entry.name().split('/').next() == Some(algorithm))
}

#[test]
fn every_combination_decrypts_what_it_encrypts() {
    let message: Vec<u8> = (0..300).map(|i| (i % 255 + 1) as u8).collect();
    for &(algorithm, key_len, block) in SIZES {
        for entry in entries_of(algorithm) {
            let mut parts = entry.name().split('/').skip(1);
            let (mode, padding) = (parts.next().unwrap(), parts.next().unwrap());
            let mut params = match mode {
                "ECB" => params(&vec![1; key_len], None),
                "CCM" | "GCM" | "OCB" => params(&vec![1; key_len], Some(&[2; 12])),
                _ => params(&vec![1; key_len], Some(&vec![2; block])),
            };
            if matches!(mode, "CCM" | "EAX" | "GCM" | "OCB") {
                params.op.tag_len = Some(block);
            }
            let message = match (mode, padding) {
                ("ECB" | "CBC", "NOPADDING") => &message[..2 * block],
                _ => &message[..],
            };
            let ciphertext = ALGO
                .cipher()
                .encrypt(entry.name(), &params, message)
                .unwrap();
            let plaintext = ALGO
                .cipher()
                .decrypt(entry.name(), &params, &ciphertext)
                .unwrap();
            assert_eq!(plaintext, message, "{}", entry.name());
        }
    }
}

#[test]
fn each_block_cipher_has_the_modes_its_block_size_takes() {
    for &(algorithm, _, block) in SIZES {
        let count = entries_of(algorithm).count();
        if count == 0 {
            continue;
        }
        // Five modes with seven paddings each, then the AEAD modes: CCM, EAX, GCM and OCB on
        // 128-bit blocks, EAX alone on 64-bit ones, none on the larger blocks of Threefish
        let aead = match block {
            16 => 4,
            8 => 1,
            _ => 0,
        };
        assert_eq!(count, 35 + aead, "{algorithm}");
    }
}

#[test]
fn every_oid_finds_its_mode_with_the_default_padding() {
    let expected = [
        ("1.2.410.200046.1.1.2", "ARIA/CBC/PKCS7PADDING"),
        ("1.2.410.200046.1.1.36", "ARIA/GCM/NOPADDING"),
        ("1.2.410.200046.1.1.39", "ARIA/CCM/NOPADDING"),
        ("1.3.6.1.4.1.3029.1.1.2", "BLOWFISH/CBC/PKCS7PADDING"),
        ("1.3.6.1.4.1.3029.1.2", "BLOWFISH/CBC/PKCS7PADDING"),
        ("1.2.392.200011.61.1.1.1.4", "CAMELLIA/CBC/PKCS7PADDING"),
        ("1.2.840.113533.7.66.10", "CAST5/CBC/PKCS7PADDING"),
        ("1.3.14.3.2.17", "DESEDE/ECB/PKCS7PADDING"),
        ("1.2.840.113549.3.7", "DESEDE/CBC/PKCS7PADDING"),
        ("1.2.643.2.2.21", "GOST28147/CBC/PKCS7PADDING"),
        ("1.3.6.1.4.1.188.7.1.1.2", "IDEA/CBC/PKCS7PADDING"),
        ("1.2.840.113549.3.2", "RC2/CBC/PKCS7PADDING"),
        ("1.2.410.200004.1.4", "SEED/CBC/PKCS7PADDING"),
    ];
    for (dotted, name) in expected {
        let algorithm = name.split('/').next().unwrap();
        if entries_of(algorithm).next().is_none() {
            continue;
        }
        let oid: tc_asn1::Asn1Oid = dotted.parse().unwrap();
        let cipher = ALGO.cipher().get_by_oid(&oid).unwrap();
        assert_eq!(cipher.entry().name(), name, "{dotted}");
    }
}

#[test]
fn bouncy_castle_aliases_find_their_ciphers() {
    for (alias, name) in [
        ("TDEA", "DESEDE/ECB/PKCS7PADDING"),
        ("gost", "GOST28147/ECB/PKCS7PADDING"),
        ("GOST-28147/CBC", "GOST28147/CBC/PKCS7PADDING"),
        ("RC5-32/CTR", "RC5/CTR/NOPADDING"),
        ("rc5_64", "RC5-64/ECB/PKCS7PADDING"),
        ("Threefish_512/CBC", "THREEFISH-512/CBC/PKCS7PADDING"),
    ] {
        let algorithm = name.split('/').next().unwrap();
        if entries_of(algorithm).next().is_none() {
            continue;
        }
        let cipher = ALGO.cipher().get_by_name(alias).unwrap();
        assert_eq!(cipher.entry().name(), name, "{alias}");
    }
}

#[cfg(feature = "threefish")]
#[test]
fn threefish_takes_no_aead_mode() {
    for name in [
        "THREEFISH-256/GCM",
        "THREEFISH-512/EAX",
        "THREEFISH-1024/OCB",
    ] {
        let error = ALGO.cipher().get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), tc_algo_old::ErrorKind::UnknownCipher, "{name}");
    }
}

#[cfg(feature = "desede")]
#[test]
fn desede_refuses_a_key_of_a_length_it_does_not_take() {
    let error = ALGO
        .cipher()
        .encrypt("DESEDE/ECB/NOPADDING", &params(&[1; 8], None), &[0; 8])
        .unwrap_err();
    assert_eq!(error.kind(), tc_algo_old::ErrorKind::InvalidParams);
}
