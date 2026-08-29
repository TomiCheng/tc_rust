//! Known-answer and behavioral tests for Salsa20 and XSalsa20.
//!
//! Vectors are copied from Bouncy Castle's `Salsa20Test` and `XSalsa20Test`.

use tc_crypto_core::StreamCipher;
use tc_stream_cipher::{
    Salsa20Engine, Salsa20Params, StreamCipherError, Xsalsa20Engine, Xsalsa20Params,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn salsa_keystream(rounds: usize, key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let params = Salsa20Params::new(key, nonce).unwrap();
    let mut engine = Salsa20Engine::with_rounds(rounds).unwrap();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; length];
    engine
        .process_bytes(&vec![0u8; length], &mut output)
        .unwrap();
    output
}

#[test]
fn salsa20_20_round_bc_vector_and_offsets() {
    let key = hex("80000000000000000000000000000000");
    let stream = salsa_keystream(20, &key, &[0u8; 8], 512);
    assert_eq!(
        &stream[0..64],
        hex("4DFA5E481DA23EA09A31022050859936\
             DA52FCEE218005164F267CB65F5CFD7F\
             2B4F97E0FF16924A52DF269515110A07\
             F9E460BC65EF95DA58F740B7D1DBB0AA")
    );
    assert_eq!(
        &stream[192..256],
        hex("DA9C1581F429E0A00F7D67E23B730676\
             783B262E8EB43A25F55FB90B3E753AEF\
             8C6713EC66C51881111593CCB3E8CB8F\
             8DE124080501EEEB389C4BCB6977CF95")
    );
    assert_eq!(
        &stream[256..320],
        hex("7D5789631EB4554400E1E025935DFA7B\
             3E9039D61BDC58A8697D36815BF1985C\
             EFDF7AE112E5BB81E37ECF0616CE7147\
             FC08A93A367E08631F23C03B00A8DA2F")
    );
    assert_eq!(
        &stream[448..512],
        hex("B375703739DACED4DD4059FD71C3C47F\
             C2F9939670FAD4A46066ADCC6A564578\
             3308B90FFB72BE04A6B147CBE38CC0C3\
             B9267C296A92A7C69873F9F263BE9703")
    );
}

#[test]
fn salsa20_12_round_bc_vector() {
    let key = hex("80000000000000000000000000000000");
    assert_eq!(
        salsa_keystream(12, &key, &[0u8; 8], 64),
        hex("FC207DBFC76C5E1774961E7A5AAD0906\
             9B2225AC1CE0FE7A0CE77003E7E5BDF8\
             B31AF821000813E6C56B8C1771D6EE70\
             39B2FBD0A68E8AD70A3944B677937897")
    );
}

#[test]
fn salsa20_8_round_bc_vector() {
    let key = hex("80000000000000000000000000000000");
    assert_eq!(
        salsa_keystream(8, &key, &[0u8; 8], 64),
        hex("A9C9F888AB552A2D1BBFF9F36BEBEB33\
             7A8B4B107C75B63BAE26CB9A235BBA9D\
             784F38BEFC3ADF4CD3E266687EA7B9F0\
             9BA650AE81EAC6063AE31FF12218DDC5")
    );
}

#[test]
fn salsa20_256_bit_key_bc_vector_and_counter_boundary() {
    let key = hex("0053A6F94C9FF24598EB3E91E4378ADD\
         3083D6297CCF2275C81B6EC11467BA0D");
    let nonce = hex("0D74DB42A91077DE");
    let stream = salsa_keystream(20, &key, &nonce, 65_600);
    assert_eq!(
        &stream[..64],
        hex("F5FAD53F79F9DF58C4AEA0D0ED9A9601\
             F278112CA7180D565B420A48019670EA\
             F24CE493A86263F677B46ACE1924773D\
             2BB25571E1AA8593758FC382B1280B71")
    );
    assert_eq!(
        &stream[65_472..65_536],
        hex("B70C50139C63332EF6E77AC54338A407\
             9B82BEC9F9A403DFEA821B83F7860791\
             650EF1B2489D0590B1DE772EEDA4E3BC\
             D60FA7CE9CD623D9D2FD5758B8653E70")
    );
    assert_eq!(
        &stream[65_536..65_600],
        hex("81582C65D7562B80AEC2F1A673A9D01C\
             9F892A23D4919F6AB47B9154E08E699B\
             4117D7C666477B60F8391481682F5D95\
             D96623DBC489D88DAA6956B9F0646B6E")
    );
}

#[test]
fn xsalsa20_bc_vector() {
    let key = hex("d5c7f6797b7e7e9c1d7fd2610b2abf2bc5a7885fb3ff78092fb3abe8986d35e2");
    let nonce = hex("744e17312b27969d826444640e9c4a378ae334f185369c95");
    let plaintext = hex("7758298c628eb3a4b6963c5445ef6697\
         1222be5d1a4ad839715d1188071739b7\
         7cc6e05d5410f963a64167629757");
    let expected = hex("27b8cfe81416a76301fd1eec6a4d9967\
         5069b2da2776c360db1bdfea7c0aa613\
         913e10f7a60fec04d11e65f2d64e");

    let params = Xsalsa20Params::new(&key, &nonce).unwrap();
    let mut engine = Xsalsa20Engine::new();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; plaintext.len()];
    engine.process_bytes(&plaintext, &mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn xsalsa20_short_bc_vector() {
    let key = hex("6799d76e5ffb5b4920bc2768bafd3f8c16554e65efcf9a16f4683a7a06927c11");
    let nonce = hex("61ab951921e54ff06d9b77f313a4e49df7a057d5fd627989");
    let params = Xsalsa20Params::new(&key, &nonce).unwrap();
    let mut engine = Xsalsa20Engine::new();
    engine.init(true, &params).unwrap();
    let mut output = [0u8; 3];
    engine.process_bytes(&hex("472766"), &mut output).unwrap();
    assert_eq!(output.as_slice(), hex("8fd7df"));
}

#[test]
fn salsa20_reset_chunking_and_single_byte_processing_match() {
    let params = Salsa20Params::new(&[0x11; 32], &[0x22; 8]).unwrap();
    let input = [0x5au8; 193];
    let mut engine = Salsa20Engine::new();
    assert_eq!(engine.algorithm_name(), "Salsa20");
    engine.init(true, &params).unwrap();
    let mut bulk = [0u8; 193];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = [0u8; 193];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}

#[test]
fn xsalsa20_reset_and_round_trip() {
    let params = Xsalsa20Params::new(&[0x33; 32], &[0x44; 24]).unwrap();
    let plaintext = [0x5au8; 193];
    let mut engine = Xsalsa20Engine::new();
    assert_eq!(engine.algorithm_name(), "XSalsa20");
    engine.init(true, &params).unwrap();
    let mut ciphertext = [0u8; 193];
    engine.process_bytes(&plaintext, &mut ciphertext).unwrap();

    engine.reset();
    let mut after_reset = [0u8; 193];
    engine.process_bytes(&plaintext, &mut after_reset).unwrap();
    assert_eq!(after_reset, ciphertext);

    engine.init(false, &params).unwrap();
    let mut recovered = [0u8; 193];
    engine.process_bytes(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn validates_rounds_parameters_and_runtime_state() {
    assert_eq!(
        Salsa20Engine::with_rounds(0).err(),
        Some(StreamCipherError::InvalidRounds(0))
    );
    assert_eq!(
        Salsa20Engine::with_rounds(7).err(),
        Some(StreamCipherError::InvalidRounds(7))
    );
    assert_eq!(
        Salsa20Engine::with_rounds(12).unwrap().algorithm_name(),
        "Salsa20/12"
    );
    assert_eq!(
        Salsa20Params::new(&[0u8; 15], &[0u8; 8]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(15)
    );
    assert_eq!(
        Salsa20Params::new(&[0u8; 16], &[0u8; 7]).unwrap_err(),
        StreamCipherError::InvalidNonceLength {
            expected: 8,
            actual: 7
        }
    );
    assert_eq!(
        Xsalsa20Params::new(&[0u8; 16], &[0u8; 24]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(16)
    );
    assert_eq!(
        Xsalsa20Params::new(&[0u8; 32], &[0u8; 23]).unwrap_err(),
        StreamCipherError::InvalidNonceLength {
            expected: 24,
            actual: 23
        }
    );

    let params = Salsa20Params::new(&[0u8; 16], &[0u8; 8]).unwrap();
    assert!(!format!("{params:?}").contains("000000"));
    let mut engine = Salsa20Engine::new();
    assert_eq!(
        engine.return_byte(0),
        Err(StreamCipherError::NotInitialised)
    );
    engine.init(true, &params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 1]),
        Err(StreamCipherError::OutputBufferTooShort)
    );
}
