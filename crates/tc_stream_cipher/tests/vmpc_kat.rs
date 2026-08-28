//! Bouncy Castle known-answer and behavioral tests for VMPC and VMPC-KSA3.

use tc_crypto_core::StreamCipher;
use tc_stream_cipher::{VmpcEngine, VmpcError, VmpcKsa3Engine, VmpcParams};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn params() -> VmpcParams {
    VmpcParams::new(
        &hex("9661410AB797D8A9EB767C21172DF6C7"),
        &hex("4B5C2F003E67F39557A8D26F3DA2B155"),
    )
    .unwrap()
}

fn assert_positions(output: &[u8], expected: &[(usize, u8)]) {
    for &(position, byte) in expected {
        assert_eq!(output[position], byte, "mismatch at position {position}");
    }
}

#[test]
fn vmpc_matches_bc_million_byte_vector() {
    let params = params();
    let input = vec![0u8; 1_000_000];
    let mut output = vec![0u8; input.len()];
    let mut engine = VmpcEngine::new();
    assert_eq!(engine.algorithm_name(), "VMPC");
    engine.init(true, &params).unwrap();
    engine.process_bytes(&input, &mut output).unwrap();

    assert_positions(
        &output,
        &[
            (0, 0xa8),
            (1, 0x24),
            (2, 0x79),
            (3, 0xf5),
            (252, 0xb8),
            (253, 0xfc),
            (254, 0x66),
            (255, 0xa4),
            (1020, 0xe0),
            (1021, 0x56),
            (1022, 0x40),
            (1023, 0xa5),
            (102_396, 0x81),
            (102_397, 0xca),
            (102_398, 0x49),
            (102_399, 0x9a),
        ],
    );

    engine.reset();
    let mut after_reset = vec![0u8; input.len()];
    engine.process_bytes(&input, &mut after_reset).unwrap();
    assert_eq!(after_reset, output);

    engine.init(false, &params).unwrap();
    let mut recovered = vec![0u8; output.len()];
    engine.process_bytes(&output, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn vmpc_ksa3_matches_bc_million_byte_vector() {
    let params = params();
    let input = vec![0u8; 1_000_000];
    let mut output = vec![0u8; input.len()];
    let mut engine = VmpcKsa3Engine::new();
    assert_eq!(engine.algorithm_name(), "VMPC-KSA3");
    engine.init(true, &params).unwrap();
    engine.process_bytes(&input, &mut output).unwrap();

    assert_positions(
        &output,
        &[
            (0, 0xb6),
            (1, 0xeb),
            (2, 0xae),
            (3, 0xfe),
            (252, 0x48),
            (253, 0x17),
            (254, 0x24),
            (255, 0x73),
            (1020, 0x1d),
            (1021, 0xae),
            (1022, 0xc3),
            (1023, 0x5a),
            (102_396, 0x1d),
            (102_397, 0xa7),
            (102_398, 0xe1),
            (102_399, 0xdc),
        ],
    );

    engine.reset();
    let mut after_reset = vec![0u8; input.len()];
    engine.process_bytes(&input, &mut after_reset).unwrap();
    assert_eq!(after_reset, output);

    engine.init(false, &params).unwrap();
    let mut recovered = vec![0u8; output.len()];
    engine.process_bytes(&output, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn vmpc_bulk_chunked_and_single_byte_processing_match() {
    let params = VmpcParams::new(&[0x11; 32], &[0x22; 48]).unwrap();
    let input = [0x5au8; 777];

    let mut bulk_engine = VmpcEngine::new();
    bulk_engine.init(true, &params).unwrap();
    let mut bulk = [0u8; 777];
    bulk_engine.process_bytes(&input, &mut bulk).unwrap();

    let mut chunked_engine = VmpcEngine::new();
    chunked_engine.init(true, &params).unwrap();
    let mut chunked = [0u8; 777];
    for (source, destination) in input.chunks(63).zip(chunked.chunks_mut(63)) {
        chunked_engine.process_bytes(source, destination).unwrap();
    }
    assert_eq!(chunked, bulk);

    let mut byte_engine = VmpcEngine::new();
    byte_engine.init(true, &params).unwrap();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| byte_engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}

#[test]
fn validates_vmpc_parameters_and_runtime_state() {
    assert!(VmpcParams::new(&[0u8; 64], &[0u8; 64]).is_ok());
    assert_eq!(
        VmpcParams::new(&[0u8; 15], &[0u8; 16]).unwrap_err(),
        VmpcError::InvalidKeyLength(15)
    );
    assert_eq!(
        VmpcParams::new(&[0u8; 65], &[0u8; 16]).unwrap_err(),
        VmpcError::InvalidKeyLength(65)
    );
    assert_eq!(
        VmpcParams::new(&[0u8; 16], &[0u8; 15]).unwrap_err(),
        VmpcError::InvalidIvLength(15)
    );
    assert_eq!(
        VmpcParams::new(&[0u8; 16], &[0u8; 65]).unwrap_err(),
        VmpcError::InvalidIvLength(65)
    );

    let mut engine = VmpcKsa3Engine::new();
    assert_eq!(engine.return_byte(0), Err(VmpcError::NotInitialised));
    assert_eq!(
        engine.process_bytes(&[0u8; 1], &mut [0u8; 1]),
        Err(VmpcError::NotInitialised)
    );
    engine.init(true, &params()).unwrap();
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 1]),
        Err(VmpcError::OutputBufferTooShort)
    );
}
