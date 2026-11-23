use tc_algo::params::{generate::RsaKeyGenParams, key::RsaKey, key::RsaKeyParams};
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::{PublicKeyAlgorithmTag, PublicKeyVersion};

#[test]
fn generates_a_matching_rsa_key_pair() {
    let tag = PublicKeyAlgorithmTag::RsaGeneral;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    assert_eq!(
        generator.generate().err().unwrap().kind(),
        tc_algo::ErrorKind::NotInitialized
    );
    generator.init(&RsaKeyGenParams::new(3072)).unwrap();
    let pair = generator.generate().unwrap();
    let public = pair.public();
    let private = pair.private();

    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let serializer = operator.serializer();
    let encoded = serializer.encode(public).unwrap();
    let decoded = serializer.decode(&encoded).unwrap();
    assert_eq!(decoded.creation_time(), public.creation_time());
    assert_eq!(decoded.version(), PublicKeyVersion::V4);
    assert_eq!(decoded.algorithm(), tag);
    assert_eq!(serializer.encode(&decoded).unwrap(), encoded);
    let decoded = decoded.key().as_any().downcast_ref::<RsaKey>().unwrap();
    let public = public.key().as_any().downcast_ref::<RsaKey>().unwrap();
    let private = private.key().as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(public.modulus().bits(), 3072);
    assert_eq!(public.modulus(), private.modulus());
    assert_eq!(decoded.modulus(), public.modulus());
    assert_eq!(decoded.exponent(), public.exponent());
    let next = generator.generate().unwrap();
    let next_public = next
        .public()
        .key()
        .as_any()
        .downcast_ref::<RsaKey>()
        .unwrap();
    assert_ne!(public.modulus(), next_public.modulus());
}

#[test]
fn the_rsa_serializer_rejects_a_noncanonical_mpi() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    // v4, RSA. The first MPI says it has nine bits but starts with its tenth bit set.
    let bytes = [0xc6, 13, 4, 0, 0, 0, 0, 1, 0, 9, 0x03, 0x81, 0, 2, 3];
    let result = operator.serializer().decode(&bytes);
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::InvalidData));
}
