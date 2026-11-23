#![cfg(feature = "cfrg-curves")]

use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::{
    ArmorKind, AsciiArmor, DecodingConfig, LiteralData, OnePassSignaturePacket, PgpRead,
    PublicKeyAlgorithmTag,
};

#[test]
fn verifies_rfc_9580_inline_signature() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let primary = [
        0xc6, 0x2a, 6, 0x63, 0x87, 0x7f, 0xe3, 27, 0, 0, 0, 32, 0xf9, 0x4d, 0xa7, 0xbb, 0x48, 0xd6,
        0x0a, 0x61, 0xe5, 0x67, 0x70, 0x6a, 0x65, 0x87, 0xd0, 0x33, 0x19, 0x99, 0xbb, 0x9d, 0x89,
        0x1a, 0x08, 0x24, 0x2e, 0xad, 0x84, 0x54, 0x3d, 0xf8, 0x95, 0xa3,
    ];
    let key = operator.serializer().decode(&primary).unwrap();
    let armor = concat!(
        "-----BEGIN PGP MESSAGE-----\n\n",
        "xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk\n",
        "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv\n",
        "bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k\n",
        "bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l\n",
        "JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ\n",
        "b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj\n",
        "FtCgazStmsuOXF9SFQE=\n",
        "-----END PGP MESSAGE-----\n",
    );
    let bytes = AsciiArmor::decode(ArmorKind::Message, armor).unwrap();
    let mut input = bytes.as_slice();
    let data = operator
        .inline_signature()
        .verify(&key, &mut input, &DecodingConfig::default())
        .unwrap();
    assert!(input.is_empty());
    assert_eq!(
        data.data(),
        b"What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n"
    );
}

#[test]
fn round_trips_binary_data_and_rejects_tampering_and_missing_signature() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator
        .key_pair_generator()
        .get_by_algorithm(PublicKeyAlgorithmTag::Ed25519)
        .unwrap();
    let keys = generator.generate().unwrap();
    let other = generator.generate().unwrap();
    let provider = operator.inline_signature();
    let literal = LiteralData::with_data(&vec![0xaa; 17000]);
    let config = DecodingConfig::default();
    let mut signed = Vec::new();
    provider
        .sign(&keys, &literal, keys.public().creation_time(), &mut signed)
        .unwrap();
    let mut framed = signed.clone();
    framed.extend_from_slice(b"next");
    let mut input = framed.as_slice();
    assert_eq!(
        provider.verify(keys.public(), &mut input, &config).unwrap(),
        literal
    );
    assert_eq!(input, b"next");

    let mut input = signed.as_slice();
    OnePassSignaturePacket::decode(&mut input, &config).unwrap();
    LiteralData::decode(&mut input, &config).unwrap();
    let signature_start = signed.len() - input.len();
    assert!(
        provider
            .verify(keys.public(), &mut &signed[..signature_start], &config)
            .is_err()
    );
    assert!(
        provider
            .verify(other.public(), &mut signed.as_slice(), &config)
            .is_err()
    );

    let mut changed = signed.clone();
    changed[signature_start - 1] ^= 1;
    assert!(
        provider
            .verify(keys.public(), &mut changed.as_slice(), &config)
            .is_err()
    );

    let mut mismatched = signed;
    // Flip the first salt octet in the leading packet, leaving the tail unchanged.
    mismatched[7] ^= 1;
    assert!(
        provider
            .verify(keys.public(), &mut mismatched.as_slice(), &config)
            .unwrap_err()
            .to_string()
            .contains("one-pass fields")
    );
}
