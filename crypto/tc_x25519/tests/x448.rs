use tc_x25519::x448::{PrivateKey, PublicKey, X448Error};

fn hex(input: &str) -> [u8; 56] {
    let mut output = [0_u8; 56];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

#[test]
fn rfc7748_section_6_2_diffie_hellman_vector() {
    let alice = PrivateKey::from_bytes(hex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5\
         74a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    let alice_public = PublicKey::from_bytes(hex(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb\
         c836647241d953d40c5b12da88120d53177f80e532c41fa0",
    ));
    let bob = PrivateKey::from_bytes(hex(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120\
         bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    ));
    let bob_public = PublicKey::from_bytes(hex(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972\
         fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
    ));
    let expected = hex(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56\
         fd2464c335543936521c24403085d59a449a5037514a879d",
    );

    assert_eq!(alice.public_key(), alice_public);
    assert_eq!(bob.public_key(), bob_public);
    assert_eq!(alice.agree(&bob_public).unwrap().into_bytes(), expected);
    assert_eq!(bob.agree(&alice_public).unwrap().into_bytes(), expected);
}

#[test]
fn low_order_public_key_is_rejected() {
    let private_key = PrivateKey::from_bytes([0xA5; 56]);
    let low_order = PublicKey::from_bytes([0_u8; 56]);

    assert!(matches!(
        private_key.agree(&low_order),
        Err(X448Error::LowOrderPoint)
    ));
}
