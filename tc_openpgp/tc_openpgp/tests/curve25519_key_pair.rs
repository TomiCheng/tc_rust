use tc_algo::params::key::{
    Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey, X25519PublicKey,
};
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::{PublicKeyAlgorithmTag, PublicKeyVersion};

#[test]
fn generates_matching_ed25519_keys() {
    let tag = PublicKeyAlgorithmTag::Ed25519;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    let (public, private) = generator.generate().unwrap().into_parts();
    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let serializer = operator.serializer();
    let mut input = serializer.encode(&public).unwrap();
    assert_eq!(input[0], 0xc6);
    input.extend_from_slice(b"next");
    let mut input = input.as_slice();
    let restored = serializer.decode_from(&mut input).unwrap();
    assert_eq!(input, b"next");
    assert_eq!(restored.algorithm(), tag);
    assert_eq!(restored.version(), PublicKeyVersion::V6);
    assert_eq!(restored.creation_time(), public.creation_time());
    let public = restored
        .key()
        .as_any()
        .downcast_ref::<Ed25519PublicKey>()
        .unwrap();
    let private = private
        .key()
        .as_any()
        .downcast_ref::<Ed25519PrivateKey>()
        .unwrap();
    assert_eq!(&private.generate_public_key(), public);
}

#[test]
fn generates_matching_x25519_keys() {
    let tag = PublicKeyAlgorithmTag::X25519;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    let (public, private) = generator.generate().unwrap().into_parts();
    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let serializer = operator.serializer();
    let mut input = serializer.encode(&public).unwrap();
    assert_eq!(input[0], 0xc6);
    input.extend_from_slice(b"next");
    let mut input = input.as_slice();
    let restored = serializer.decode_from(&mut input).unwrap();
    assert_eq!(input, b"next");
    assert_eq!(restored.algorithm(), tag);
    assert_eq!(restored.version(), PublicKeyVersion::V6);
    assert_eq!(restored.creation_time(), public.creation_time());
    let public = restored
        .key()
        .as_any()
        .downcast_ref::<X25519PublicKey>()
        .unwrap();
    let private = private
        .key()
        .as_any()
        .downcast_ref::<X25519PrivateKey>()
        .unwrap();
    assert_eq!(&private.generate_public_key(), public);
}

#[test]
fn the_rfc_version_six_ed25519_primary_key_round_trips_byte_for_byte() {
    // RFC 9580 Appendix A.3, the first packet before the Direct Key signature.
    let bytes = [
        0xc6, 0x2a, 6, 0x63, 0x87, 0x7f, 0xe3, 27, 0, 0, 0, 32, 0xf9, 0x4d, 0xa7, 0xbb, 0x48, 0xd6,
        0x0a, 0x61, 0xe5, 0x67, 0x70, 0x6a, 0x65, 0x87, 0xd0, 0x33, 0x19, 0x99, 0xbb, 0x9d, 0x89,
        0x1a, 0x08, 0x24, 0x2e, 0xad, 0x84, 0x54, 0x3d, 0xf8, 0x95, 0xa3,
    ];
    let operator = DefaultPgpOperatorBuilder::default().build();
    let serializer = operator.serializer();
    let public = serializer.decode(&bytes).unwrap();
    assert_eq!(public.algorithm(), PublicKeyAlgorithmTag::Ed25519);
    assert_eq!(public.version(), PublicKeyVersion::V6);
    assert_eq!(public.creation_time(), 0x6387_7fe3);
    let key = public
        .key()
        .as_any()
        .downcast_ref::<Ed25519PublicKey>()
        .unwrap();
    assert_eq!(&key.a()[..], &bytes[12..]);
    assert_eq!(serializer.encode(&public).unwrap(), bytes);
}

#[test]
fn a_generated_ed25519_key_signs_binary_data_and_checks_the_detached_signature() {
    use tc_openpgp_packet::{
        ArmorKind, AsciiArmor, DecodingConfig, EncodingConfig, PgpRead, PgpWrite, SignaturePacket,
    };

    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator
        .key_pair_generator()
        .get_by_algorithm(PublicKeyAlgorithmTag::Ed25519)
        .unwrap();
    let keys = generator.generate().unwrap();
    let serializer = operator.serializer();
    let armored_key = serializer.encode_armored(keys.public()).unwrap();
    let public = serializer.decode_armored(&armored_key).unwrap();
    assert_eq!(
        serializer.encode(&public).unwrap(),
        serializer.encode(keys.public()).unwrap()
    );

    let provider = operator.detached_signature();
    let creation = public.creation_time();
    let document = b"binary\x00message\r\n";
    let signed = provider
        .sign(&keys, &mut document.as_slice(), creation)
        .unwrap();
    let mut bytes = Vec::new();
    signed
        .encode(&mut bytes, &EncodingConfig::default())
        .unwrap();
    let armor = AsciiArmor::encode(ArmorKind::Signature, &bytes).unwrap();
    let bytes = AsciiArmor::decode(ArmorKind::Signature, &armor).unwrap();
    let packet =
        SignaturePacket::decode(&mut bytes.as_slice(), &DecodingConfig::default()).unwrap();
    assert_eq!(packet, signed);
    assert!(
        provider
            .verify(&public, &mut document.as_slice(), &packet)
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &mut &b"modified\x00message\r\n"[..], &packet)
            .unwrap()
    );
    let mut unknown_critical = packet.hashed_subpackets().to_vec();
    unknown_critical.extend_from_slice(&[1, 0xff]);
    let unknown_critical = packet.with_subpackets(unknown_critical, Vec::new());
    let result = provider.verify(&public, &mut document.as_slice(), &unknown_critical);
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::Unsupported));
}

#[test]
fn the_rfc_version_six_ed25519_text_signature_verifies_with_normalized_line_endings() {
    use std::io::Read;
    use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, PgpRead, SignaturePacket};

    // RFC 9580 Appendix A.3 primary key and Appendix A.6 detached signature.
    let armored_key = concat!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
        "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laM=\n",
        "-----END PGP PUBLIC KEY BLOCK-----\n",
    );
    let armored_signature = concat!(
        "-----BEGIN PGP SIGNATURE-----\n\n",
        "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n",
        "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo\n",
        "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr\n",
        "NK2ay45cX1IVAQ==\n",
        "-----END PGP SIGNATURE-----\n",
    );
    let operator = DefaultPgpOperatorBuilder::default().build();
    let public = operator.serializer().decode_armored(armored_key).unwrap();
    let bytes = AsciiArmor::decode(ArmorKind::Signature, armored_signature).unwrap();
    let packet =
        SignaturePacket::decode(&mut bytes.as_slice(), &DecodingConfig::default()).unwrap();
    let document = b"What we need from the grocery store:\n\n- tofu\r\n- vegetables\n- noodles\n";

    struct OneByte<'a>(&'a [u8]);

    impl Read for OneByte<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let limit = bytes.len().min(1);
            self.0.read(&mut bytes[..limit])
        }
    }

    assert!(
        operator
            .detached_signature()
            .verify(&public, &mut OneByte(document), &packet)
            .unwrap()
    );
}
