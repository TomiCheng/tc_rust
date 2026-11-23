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
