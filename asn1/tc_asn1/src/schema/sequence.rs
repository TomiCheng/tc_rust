// use crate::{Encode, EncodingOptions};
// 
// pub trait SequenceFields {
//     fn fields(&self, rules: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode));
// }
// 
// #[macro_export]
// macro_rules! impl_sequence_encode {
//     ($t:ty) => {
//         $crate::impl_sequence_encode!($t, $crate::tag::SEQUENCE);
//     };
//     ($t:ty, $tag:expr) => {
//         impl $crate::EncodeContent for $t {
//             /// 累加欄位的完整 TLV 長度。變動時間：分支只依編碼結構。
//             fn content_len(&self, rules: &$crate::EncodingOptions) -> usize {
//                 let mut total = 0;
//                 $crate::SequenceFields::fields(self, rules, &mut |field| {
//                     total += field.encoded_len(rules)
//                 });
//                 total
//             }
// 
//             /// 依序寫入欄位，回傳第一個編碼錯誤。變動時間：分支只依編碼結構。
//             fn encode_content(
//                 &self,
//                 rules: &$crate::EncodingOptions,
//                 out: &mut [u8],
//             ) -> ::core::result::Result<usize, $crate::Asn1Error> {
//                 let len = $crate::EncodeContent::content_len(self, rules);
//                 let out = out
//                     .get_mut(..len)
//                     .ok_or($crate::Asn1Error::BufferTooSmall)?;
//                 let mut at = 0;
//                 let mut error = ::core::option::Option::None;
//                 $crate::SequenceFields::fields(self, rules, &mut |field| {
//                     if error.is_none() {
//                         match field.encode(rules, &mut out[at..]) {
//                             ::core::result::Result::Ok(n) => at += n,
//                             ::core::result::Result::Err(e) => {
//                                 error = ::core::option::Option::Some(e)
//                             }
//                         }
//                     }
//                 });
//                 error.map_or(::core::result::Result::Ok(at), ::core::result::Result::Err)
//             }
//         }
// 
//         impl $crate::EncodeTagged for $t {}
// 
//         impl $crate::Encode for $t {
//             fn encoded_len(&self, rules: &$crate::EncodingOptions) -> usize {
//                 $crate::EncodeTagged::encoded_len_tagged(self, $tag, rules)
//             }
// 
//             fn encode(
//                 &self,
//                 rules: &$crate::EncodingOptions,
//                 out: &mut [u8],
//             ) -> ::core::result::Result<usize, $crate::Asn1Error> {
//                 $crate::EncodeTagged::encode_tagged(self, $tag, rules, out)
//             }
//         }
//     };
// }
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::EncodeContent;
//     use crate::EncodingType;
//     use crate::{Asn1Boolean, Asn1Error, Asn1Integer, Explicit, Implicit};
//     struct Pair(Asn1Boolean, Asn1Integer);
//     impl SequenceFields for Pair {
//         fn fields(&self, _: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
//             sink(&self.0);
//             sink(&self.1);
//         }
//     }
//     crate::impl_sequence_encode!(Pair);
//     #[test]
//     fn the_sequence_macro_encodes_two_fields_in_schema_order() {
//         let value = Pair(Asn1Boolean::from(true), 5_u8.into());
//         let mut out = [0; 8];
//         assert_eq!(
//             value.encode(&EncodingOptions::new(EncodingType::Der), &mut out),
//             Ok(8)
//         );
//         assert_eq!(out, [0x30, 6, 1, 1, 255, 2, 1, 5]);
//     }
//     struct Tagged;
//     impl SequenceFields for Tagged {
//         fn fields(&self, rules: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
//             if rules.encoding_type() == EncodingType::Ber(crate::LengthForm::Definite) {
//                 sink(&Implicit::new(&[0x80], &Asn1Boolean::from(false)));
//             }
//             sink(&Explicit::new(&[0xA0], &Asn1Boolean::from(true)));
//         }
//     }
//     crate::impl_sequence_encode!(Tagged, &[0x60]);
//     #[test]
//     fn custom_tags_temporary_wrappers_and_rule_dependent_fields_work_together() {
//         for (rules, expected) in [
//             (
//                 &EncodingOptions::new(EncodingType::Der),
//                 &[0x60, 5, 0xA0, 3, 1, 1, 255][..],
//             ),
//             (
//                 &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
//                 &[0x60, 8, 0x80, 1, 0, 0xA0, 3, 1, 1, 255],
//             ),
//         ] {
//             let mut out = alloc::vec![0; Tagged.encoded_len(rules)];
//             Tagged.encode(rules, &mut out).unwrap();
//             assert_eq!(out, expected);
//         }
//     }
//     #[test]
//     fn the_first_encoding_error_prevents_later_fields_from_being_written() {
//         struct Fail;
//         impl crate::EncodeContent for Fail {
//             fn content_len(&self, _: &EncodingOptions) -> usize {
//                 0
//             }
// 
//             fn encode_content(
//                 &self,
//                 _: &EncodingOptions,
//                 _: &mut [u8],
//             ) -> Result<usize, Asn1Error> {
//                 Err(Asn1Error::MalformedValue)
//             }
//         }
// 
//         impl crate::EncodeTagged for Fail {}
// 
//         impl Encode for Fail {
//             fn encoded_len(&self, rules: &EncodingOptions) -> usize {
//                 crate::EncodeTagged::encoded_len_tagged(self, &[5], rules)
//             }
// 
//             fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
//                 crate::EncodeTagged::encode_tagged(self, &[5], rules, out)
//             }
//         }
//         struct FailedSequence;
//         impl SequenceFields for FailedSequence {
//             fn fields(&self, _: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
//                 sink(&Fail);
//                 sink(&Asn1Boolean::from(true));
//             }
//         }
//         crate::impl_sequence_encode!(FailedSequence);
//         let mut out = [0xAA; 5];
//         assert_eq!(
//             FailedSequence.encode_content(&EncodingOptions::new(EncodingType::Der), &mut out),
//             Err(Asn1Error::MalformedValue)
//         );
//         assert_eq!(&out[2..], &[0xAA; 3]);
//     }
// }
