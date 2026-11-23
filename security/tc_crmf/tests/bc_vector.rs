use std::sync::Arc;

use tc_asn1::{Decode, DecodingOptions};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_crmf::CertificateRequestMessage;
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

fn hex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn the_jvm_message_verifies_and_flipping_byte_seven_invalidates_its_signature() {
    let public_key = hex(JVM_PUBLIC_KEY);
    let (used, public_key_info) =
        SubjectPublicKeyInfo::decode_der(&public_key, &DecodingOptions::default()).unwrap();
    assert_eq!(used, public_key.len());
    let x509 = DefaultX509OperatorBuilder::default().build();
    let public = x509.spki().decode(&public_key_info).unwrap();
    let verifier = x509.verifier_factory_provider(Arc::from(public));

    let mut bytes = hex(JVM_MESSAGE);
    let request = CertificateRequestMessage::decode(&bytes).unwrap();
    assert_eq!(request.encode().unwrap(), bytes);
    assert!(request.is_valid_signing_key_pop(&*verifier).unwrap());

    bytes[7] ^= 1;
    let request = CertificateRequestMessage::decode(&bytes).unwrap();
    assert!(!request.is_valid_signing_key_pop(&*verifier).unwrap());

    bytes.push(0);
    assert!(CertificateRequestMessage::decode(&bytes).is_err());
}

// From bc-csharp/crypto/test/src/crmf/test/CrmfTest.cs, MessageFromJVM.
const JVM_PUBLIC_KEY: &str = "305c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001";
const JVM_MESSAGE: &str = "3081cc30760201013071a511300f310d300b0603550403130454657374a65c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001a152300d06092a864886f70d01010505000341003120cdb58edfef4a2e1a4bfe96b972007c1d1c949221d266efe28b45ba036b9d534f5dca261dce8f21e134d97e55c3bd76d1460781fd9703f8f9907d1f036c20";
