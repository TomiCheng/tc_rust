// use tc_asn1::{Asn1Boolean, Asn1Error, Decode, DecodeInner, DecodingContext, DecodingOptions};
// use tc_asn1_x509::{AlgorithmIdentifier, DigestInfo, Extension};
//
// #[test]
// fn algorithm_parameters_are_validated_as_der_even_when_stored_as_any() {
//     let options = DecodingOptions::default();
//     for wire in [
//         &[0x30, 7, 6, 2, 42, 3, 1, 1, 1][..],
//         &[0x30, 7, 6, 2, 42, 3, 5, 0x81, 0],
//     ] {
//         assert!(AlgorithmIdentifier::decode(wire, &options).is_ok());
//         assert!(
//             AlgorithmIdentifier::decode_inner_der(wire, &mut DecodingContext::new(&options))
//                 .is_err()
//         );
//     }
//     assert!(
//         AlgorithmIdentifier::decode_inner_der(
//             &[0x30, 6, 6, 2, 42, 3, 5, 0],
//             &mut DecodingContext::new(&options)
//         )
//         .is_ok()
//     );
// }
//
// #[test]
// fn digest_info_der_propagates_to_the_algorithm_identifier() {
//     let wire = [0x30, 11, 0x30, 7, 6, 2, 42, 3, 1, 1, 1, 4, 0];
//     let options = DecodingOptions::default();
//     assert!(DigestInfo::decode(&wire, &options).is_ok());
//     assert!(DigestInfo::decode_inner_der(&wire, &mut DecodingContext::new(&options)).is_err());
// }
//
// #[test]
// fn der_extensions_reject_explicit_default_values() {
//     let wire = [0x30, 9, 6, 2, 42, 3, 1, 1, 0, 4, 0];
//     let options = DecodingOptions::default();
//     assert!(Extension::decode(&wire, &options).is_ok());
//     assert_eq!(
//         Extension::decode_inner_der(&wire, &mut DecodingContext::new(&options)).unwrap_err(),
//         Asn1Error::NotDer
//     );
//     assert!(
//         Extension::decode_inner_der(
//             &[0x30, 6, 6, 2, 42, 3, 4, 0],
//             &mut DecodingContext::new(&options)
//         )
//         .is_ok()
//     );
// }
//
// #[test]
// fn decoding_an_extension_value_enforces_its_embedded_der_contract() {
//     let options = DecodingOptions::default();
//     let extension = Extension::new("1.2.3".parse().unwrap(), false, &[1, 1, 1]);
//     assert_eq!(
//         extension.extn_value_as::<Asn1Boolean>(&mut DecodingContext::new(&options)),
//         Err(Asn1Error::NotDer)
//     );
//     let extension = Extension::new("1.2.3".parse().unwrap(), false, &[1, 1, 255]);
//     assert!(
//         extension
//             .extn_value_as::<Asn1Boolean>(&mut DecodingContext::new(&options))
//             .unwrap()
//             .is_true()
//     );
// }
