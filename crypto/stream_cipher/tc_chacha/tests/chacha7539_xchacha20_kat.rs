mod common;

use tc_chacha::{ChaCha7539Engine, XChaCha20Engine};
use tc_cipher::{CipherDirection, StreamCipher, StreamCipherInit};
use tc_params::KeyWithIvRef;

use common::unhex;

#[test]
fn chacha7539_matches_rfc_8439_vector() {
    let key = unhex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    let iv = unhex("000000000000004a00000000");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = unhex(
        "6e2e359a2568f98041ba0728dd0d6981
         e97e7aec1d4360c20a27afccfd9fae0b
         f91b65c5524733ab8f593dabcd62b357
         1639d624e65152ab8f530c359f0861d8
         07ca0dbf500d6a6156a38e088a22b65e
         52bc514d16ccf806818ce91ab7793736
         5af90bbf74a35be6b40b8eedf2785e42
         874d",
    );

    let mut engine = ChaCha7539Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
        .unwrap();

    // RFC 8439 starts at block counter one; the stream engine starts at zero.
    let mut input = vec![0u8; 64 + plaintext.len()];
    input[64..].copy_from_slice(plaintext);
    let mut output = vec![0u8; input.len()];
    engine.process_bytes(&input, &mut output).unwrap();
    assert_eq!(&output[64..], expected);
}

#[test]
fn chacha7539_reset_chunking_and_directions_match() {
    let params = KeyWithIvRef::new(&[0x11; 32], &[0x22; 12]);
    let input = [0x5a; 193];
    let mut engine = ChaCha7539Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut bulk = [0u8; 193];
    engine.process_bytes(&input, &mut bulk).unwrap();
    engine.reset();

    let mut chunked = [0u8; 193];
    engine
        .process_bytes(&input[..63], &mut chunked[..63])
        .unwrap();
    engine
        .process_bytes(&input[63..], &mut chunked[63..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 193];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn xchacha20_matches_draft_stream_vector() {
    let key = unhex("808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f");
    let iv = unhex("404142434445464748494a4b4c4d4e4f 5051525354555657");
    let plaintext = unhex(
        "4c616469657320616e642047656e746c
         656d656e206f662074686520636c6173
         73206f66202739393a20496620492063
         6f756c64206f6666657220796f75206f
         6e6c79206f6e652074697020666f7220
         746865206675747572652c2073756e73
         637265656e20776f756c642062652069
         742e",
    );
    let expected = unhex(
        "bd6d179d3e83d43b9576579493c0e939
         572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39
         ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e
         3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13
         b52e",
    );

    let params = KeyWithIvRef::new(&key, &iv);
    let mut engine = XChaCha20Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    // The AEAD vector reserves block zero for the Poly1305 key.
    let mut input = vec![0u8; 64 + plaintext.len()];
    input[64..].copy_from_slice(&plaintext);
    let mut output = vec![0u8; input.len()];
    engine.process_bytes(&input, &mut output).unwrap();
    assert_eq!(&output[64..], expected);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; output.len()];
    engine.process_bytes(&output, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn xchacha20_reset_chunking_and_single_bytes_match() {
    let params = KeyWithIvRef::new(&[0x33; 32], &[0x44; 24]);
    let input = [0xa5; 257];
    let mut engine = XChaCha20Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut bulk = [0u8; 257];
    engine.process_bytes(&input, &mut bulk).unwrap();
    engine.reset();

    let mut chunked = [0u8; 257];
    for (source, destination) in input.chunks(65).zip(chunked.chunks_mut(65)) {
        engine.process_bytes(source, destination).unwrap();
    }
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}
