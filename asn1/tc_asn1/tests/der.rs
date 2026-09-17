// use tc_asn1::*;
// 
// fn der<'a, T: DecodeInner<'a>>(wire: &'a [u8]) -> Result<T, Asn1Error> {
//     T::decode_inner_der(wire, &mut DecodingContext::new(&DecodingOptions::default()))
//         .map(|(_, value)| value)
// }
// 
// #[test]
// fn der_boolean_accepts_only_the_canonical_true_octet() {
//     let options = DecodingOptions::default();
//     let mut context = DecodingContext::new(&options);
//     for byte in 0..=255 {
//         assert_eq!(
//             Asn1Boolean::decode_content(&[byte], &mut context)
//                 .unwrap()
//                 .is_true(),
//             byte != 0
//         );
//         let result = Asn1Boolean::decode_content_der(&[byte], &mut context);
//         if byte == 0 || byte == 255 {
//             assert_eq!(result.unwrap().is_true(), byte != 0);
//         } else {
//             assert_eq!(result, Err(Asn1Error::NotDer));
//         }
//     }
// }
// 
// #[test]
// fn der_checks_headers_and_encoding_forms_even_with_implicit_tags() {
//     for wire in [&[0x80, 0x81, 1, 0xff][..], &[0x80, 0x82, 0, 1, 0xff]] {
//         assert!(Asn1Boolean::decode(wire, &DecodingOptions::default()).is_ok());
//         assert_eq!(der::<Asn1Boolean>(wire), Err(Asn1Error::NotDer));
//     }
//     for wire in [
//         &[0x24, 3, 4, 1, 42][..],
//         &[0xa0, 3, 4, 1, 42],
//         &[0xa0, 0x80, 4, 1, 42, 0, 0],
//     ] {
//         assert!(Asn1OctetString::decode(wire, &DecodingOptions::default()).is_ok());
//         assert_eq!(der::<Asn1OctetString>(wire), Err(Asn1Error::NotDer));
//     }
//     assert!(der::<Asn1OctetString>(&[0x80, 1, 42]).is_ok());
//     assert!(der::<Asn1Any>(&[0x22, 0]).is_err());
//     assert_eq!(der::<Asn1Any>(&[0, 0]), Err(Asn1Error::NotDer));
// }
// 
// #[test]
// fn der_parent_decoders_reject_non_der_children_at_every_level() {
//     type Nested = Asn1SequenceOf<Asn1SequenceOf<Asn1Boolean>>;
//     for wire in [
//         &[0x30, 5, 0x30, 3, 1, 1, 1][..],
//         &[0x30, 6, 0x30, 4, 1, 0x81, 1, 255],
//     ] {
//         assert!(Nested::decode(wire, &DecodingOptions::default()).is_ok());
//         assert!(der::<Nested>(wire).is_err());
//         assert!(der::<Asn1Any>(wire).is_err());
//         assert!(der::<Asn1Object>(wire).is_err());
//     }
//     assert!(der::<Nested>(&[0x30, 5, 0x30, 3, 1, 1, 255]).is_ok());
// }
// 
// #[test]
// fn schema_fields_select_der_independently_without_changing_the_context() {
//     let options = DecodingOptions::default();
//     let mut context = DecodingContext::new(&options);
//     let mut fields = Fields::new(&[1, 1, 1, 1, 1, 255, 1, 1, 2], &mut context).unwrap();
//     assert!(
//         fields
//             .required::<Asn1Boolean>(Asn1Boolean::TAG)
//             .unwrap()
//             .is_true()
//     );
//     assert!(
//         fields
//             .required_der::<Asn1Boolean>(Asn1Boolean::TAG)
//             .unwrap()
//             .is_true()
//     );
//     assert!(
//         fields
//             .required::<Asn1Boolean>(Asn1Boolean::TAG)
//             .unwrap()
//             .is_true()
//     );
//     fields.finish().unwrap();
//     assert_eq!(context.depth(), 0);
// 
//     let mut fields = Fields::new(&[1, 1, 1, 1, 1, 2], &mut context).unwrap();
//     assert_eq!(
//         fields.required_der::<Asn1Boolean>(Asn1Boolean::TAG),
//         Err(Asn1Error::NotDer)
//     );
//     assert!(
//         fields
//             .required::<Asn1Boolean>(Asn1Boolean::TAG)
//             .unwrap()
//             .is_true()
//     );
//     fields.finish().unwrap();
// }
// 
// #[test]
// fn der_fields_validate_implicit_contents_explicit_headers_and_default_omission() {
//     let options = DecodingOptions::default();
//     let mut context = DecodingContext::new(&options);
//     assert_eq!(
//         Fields::new(&[0x80, 1, 1], &mut context)
//             .unwrap()
//             .implicit_der::<Asn1Boolean>(&[0x80]),
//         Err(Asn1Error::NotDer)
//     );
//     assert_eq!(
//         Fields::new(&[0xa0, 0x81, 3, 1, 1, 255], &mut context)
//             .unwrap()
//             .explicit_der::<Asn1Boolean>(&[0xa0]),
//         Err(Asn1Error::NotDer)
//     );
//     assert_eq!(
//         Fields::new(&[1, 1, 0], &mut context)
//             .unwrap()
//             .default_der(Asn1Boolean::TAG, Asn1Boolean::from(false)),
//         Err(Asn1Error::NotDer)
//     );
//     let mut fields = Fields::new(&[], &mut context).unwrap();
//     assert!(
//         !fields
//             .default_der(Asn1Boolean::TAG, Asn1Boolean::from(false))
//             .unwrap()
//             .is_true()
//     );
//     fields.finish().unwrap();
//     assert_eq!(context.depth(), 0);
// }
// 
// #[test]
// fn der_set_of_requires_lexicographic_order_and_der_members() {
//     type Set = Asn1SetOf<Asn1Boolean>;
//     assert!(der::<Set>(&[0x31, 6, 1, 1, 0, 1, 1, 255]).is_ok());
//     for wire in [&[0x31, 6, 1, 1, 255, 1, 1, 0][..], &[0x31, 3, 1, 1, 1]] {
//         assert!(Set::decode(wire, &DecodingOptions::default()).is_ok());
//         assert_eq!(der::<Set>(wire), Err(Asn1Error::NotDer));
//     }
// }
// 
// #[test]
// fn der_bit_strings_reject_nonzero_padding_bits() {
//     let wire = [3, 2, 3, 0xff];
//     assert!(Asn1BitString::decode(&wire, &DecodingOptions::default()).is_ok());
//     assert_eq!(der::<Asn1BitString>(&wire), Err(Asn1Error::NotDer));
//     assert!(der::<Asn1BitString>(&[3, 2, 3, 0xf8]).is_ok());
// }
// 
// #[test]
// fn nested_decoders_share_depth_and_restore_it_after_success_or_failure() {
//     type Nested = Asn1SequenceOf<Asn1SequenceOf<Asn1Null>>;
//     let wire = [0x30, 4, 0x30, 2, 5, 0];
//     let options = DecodingOptions::new(1, 1024, 8);
//     let mut context = DecodingContext::new(&options);
//     assert_eq!(
//         Nested::decode_inner(&wire, &mut context),
//         Err(Asn1Error::DepthExceeded)
//     );
//     assert_eq!(context.depth(), 0);
//     assert_eq!(
//         Nested::decode_inner_der(&wire, &mut context),
//         Err(Asn1Error::DepthExceeded)
//     );
//     assert_eq!(context.depth(), 0);
//     let options = DecodingOptions::new(2, 1024, 8);
//     let mut context = DecodingContext::new(&options);
//     assert!(Nested::decode_inner_der(&wire, &mut context).is_ok());
//     assert_eq!(context.depth(), 0);
//     assert!(
//         Asn1SequenceOf::<Asn1Null>::decode_inner_der(&[0x30, 4, 5, 0, 5, 0], &mut context).is_ok()
//     );
//     assert_eq!(context.depth(), 0);
// }
// 
// #[test]
// fn inner_decoders_can_borrow_input_longer_than_the_options_live() {
//     struct Borrowed<'a>(&'a [u8]);
//     impl<'a> DecodeInner<'a> for Borrowed<'a> {
//         fn decode_inner(
//             wire: &'a [u8],
//             context: &mut DecodingContext<'_>,
//         ) -> Result<(usize, Self), Asn1Error> {
//             let element = Asn1Ref::parse(wire, context)?;
//             Ok((element.total_len(), Self(element.value())))
//         }
//         fn decode_inner_der(
//             wire: &'a [u8],
//             context: &mut DecodingContext<'_>,
//         ) -> Result<(usize, Self), Asn1Error> {
//             let element = Asn1Ref::parse_der(wire, context)?;
//             Ok((element.total_len(), Self(element.value())))
//         }
//     }
//     let wire = [0x80, 1, 42];
//     let borrowed = {
//         let options = DecodingOptions::default();
//         Borrowed::decode_inner_der(&wire, &mut DecodingContext::new(&options))
//             .unwrap()
//             .1
//     };
//     assert_eq!(borrowed.0, &[42]);
// }
