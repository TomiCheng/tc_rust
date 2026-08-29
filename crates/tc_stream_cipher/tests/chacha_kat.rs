//! Known-answer and behavioral tests for the original ChaCha stream cipher.
//!
//! Vectors are copied from Bouncy Castle's `ChaChaTest`, generated with the
//! eSTREAM ChaCha reference implementation.

use tc_cipher_core::{StreamCipher, StreamCipherInit};
use tc_stream_cipher::{ChaChaEngine, ChaChaParams, StreamCipherError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn keystream(rounds: usize, key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let params = ChaChaParams::new(key, nonce).unwrap();
    let mut engine = ChaChaEngine::with_rounds(rounds).unwrap();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; length];
    engine
        .process_bytes(&vec![0u8; length], &mut output)
        .unwrap();
    output
}

#[test]
fn chacha20_bc_vector_and_offsets() {
    let key = hex("80000000000000000000000000000000");
    let stream = keystream(20, &key, &[0u8; 8], 512);
    assert_eq!(
        &stream[..64],
        hex("FBB87FBB8395E05DAA3B1D683C422046\
             F913985C2AD9B23CFC06C1D8D04FF213\
             D44A7A7CDB84929F915420A8A3DC58BF\
             0F7ECB4B1F167BB1A5E6153FDAF4493D")
    );
    assert_eq!(
        &stream[192..256],
        hex("D9485D55B8B82D792ED1EEA8E93E9BC1\
             E2834AD0D9B11F3477F6E106A2F6A5F2\
             EA8244D5B925B8050EAB038F58D4DF57\
             7FAFD1B89359DAE508B2B10CBD6B488E")
    );
    assert_eq!(
        &stream[256..320],
        hex("08661A35D6F02D3D9ACA8087F421F7C8\
             A42579047D6955D937925BA21396DDD4\
             74B1FC4ACCDCAA33025B4BCE817A4FBF\
             3E5D07D151D7E6FE04934ED466BA4779")
    );
    assert_eq!(
        &stream[448..512],
        hex("A7E16DD38BA48CCB130E5BE9740CE359\
             D631E91600F85C8A5D0785A612D1D987\
             90780ACDDC26B69AB106CCF6D866411D\
             10637483DBF08CC5591FD8B3C87A3AE0")
    );
}

#[test]
fn chacha12_bc_vector() {
    let key = hex("80000000000000000000000000000000");
    assert_eq!(
        keystream(12, &key, &[0u8; 8], 64),
        hex("36CF0D56E9F7FBF287BC5460D95FBA94\
             AA6CBF17D74E7C784DDCF7E0E882DDAE\
             3B5A58243EF32B79A04575A8E2C2B73D\
             C64A52AA15B9F88305A8F0CA0B5A1A25")
    );
}

#[test]
fn chacha8_bc_vector() {
    let key = hex("80000000000000000000000000000000");
    assert_eq!(
        keystream(8, &key, &[0u8; 8], 64),
        hex("BEB1E81E0F747E43EE51922B3E87FB38\
             D0163907B4ED49336032AB78B67C2457\
             9FE28F751BD3703E51D876C017FAA435\
             89E63593E03355A7D57B2366F30047C5")
    );
}

#[test]
fn chacha_256_bit_key_bc_vector_and_counter_boundary() {
    let key = hex("0053A6F94C9FF24598EB3E91E4378ADD\
         3083D6297CCF2275C81B6EC11467BA0D");
    let nonce = hex("0D74DB42A91077DE");
    let stream = keystream(20, &key, &nonce, 65_600);
    assert_eq!(
        &stream[..64],
        hex("57459975BC46799394788DE80B928387\
             862985A269B9E8E77801DE9D874B3F51\
             AC4610B9F9BEE8CF8CACD8B5AD0BF17D\
             3DDF23FD7424887EB3F81405BD498CC3")
    );
    assert_eq!(
        &stream[65_472..65_536],
        hex("EF9AEC58ACE7DB427DF012B2B91A0C1E\
             8E4759DCE9CDB00A2BD59207357BA06C\
             E02D327C7719E83D6348A6104B081DB0\
             3908E5186986AE41E3AE95298BB7B713")
    );
    assert_eq!(
        &stream[65_536..65_600],
        hex("17EF5FF454D85ABBBA280F3A94F1D26E\
             950C7D5B05C4BB3A78326E0DC5731F83\
             84205C32DB867D1B476CE121A0D7074B\
             AA7EE90525D15300F48EC0A6624BD0AF")
    );
}

#[test]
fn reset_chunking_and_single_byte_processing_match() {
    let params = ChaChaParams::new(&[0x11; 32], &[0x22; 8]).unwrap();
    let input = [0x5au8; 193];
    let mut engine = ChaChaEngine::new();
    assert_eq!(engine.algorithm_name(), "ChaCha20");
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
fn encrypt_decrypt_round_trips() {
    let params = ChaChaParams::new(&[0x33; 16], &[0x44; 8]).unwrap();
    let plaintext = b"Original ChaCha uses a 64-bit nonce and counter";
    let mut engine = ChaChaEngine::new();
    engine.init(true, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    engine.process_bytes(plaintext, &mut ciphertext).unwrap();

    engine.init(false, &params).unwrap();
    let mut recovered = vec![0u8; plaintext.len()];
    engine.process_bytes(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn validates_rounds_parameters_and_runtime_state() {
    assert_eq!(
        ChaChaEngine::with_rounds(0).err(),
        Some(StreamCipherError::InvalidRounds(0))
    );
    assert_eq!(
        ChaChaEngine::with_rounds(7).err(),
        Some(StreamCipherError::InvalidRounds(7))
    );
    assert_eq!(
        ChaChaEngine::with_rounds(12).unwrap().algorithm_name(),
        "ChaCha12"
    );
    assert_eq!(
        ChaChaParams::new(&[0u8; 15], &[0u8; 8]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(15)
    );
    assert_eq!(
        ChaChaParams::new(&[0u8; 16], &[0u8; 7]).unwrap_err(),
        StreamCipherError::InvalidNonceLength {
            expected: 8,
            actual: 7
        }
    );

    let params = ChaChaParams::new(&[0u8; 16], &[0u8; 8]).unwrap();
    assert!(!format!("{params:?}").contains("000000"));
    let mut engine = ChaChaEngine::new();
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
