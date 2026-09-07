use tc_x25519::x25519::{PrivateKey, PublicKey, X25519Error};

fn hex(input: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

#[test]
fn rfc7748_section_6_1_diffie_hellman_vector() {
    let alice = PrivateKey::from_bytes(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let alice_public = PublicKey::from_bytes(hex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ));
    let bob = PrivateKey::from_bytes(hex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let bob_public = PublicKey::from_bytes(hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ));
    let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(alice.public_key(), alice_public);
    assert_eq!(bob.public_key(), bob_public);
    assert_eq!(alice.agree(&bob_public).unwrap().into_bytes(), expected);
    assert_eq!(bob.agree(&alice_public).unwrap().into_bytes(), expected);
}

#[test]
fn low_order_public_key_is_rejected() {
    let private_key = PrivateKey::from_bytes([0xA5; 32]);
    let low_order = PublicKey::from_bytes([0_u8; 32]);

    assert!(matches!(
        private_key.agree(&low_order),
        Err(X25519Error::LowOrderPoint)
    ));
}
