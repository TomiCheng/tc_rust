// use alloc::boxed::Box;
// use core::fmt;
//
// use tc_asn1::tag::NULL;
// use tc_asn1::{
//     Asn1Any, Asn1Error, Asn1Null, Asn1Oid, DecodeContent, DecodingContext, Encode, EncodingOptions,
//     Fields, SequenceFields,
// };
//
// pub enum AlgorithmParameters {
//     /// 沒有參數。
//     Absent,
//     /// `NULL`。光看 tag 就認得，不必查演算法，所以解碼時直接是它。
//     Null,
//     /// 自己造的：型別知道，只需要寫出去。
//     Built(Box<dyn Encode>),
//     /// 解進來的、不是 NULL 的：型別待查，用的時候照 `algorithm` 去 `decode_as`。
//     Decoded(Asn1Any),
// }
//
// impl fmt::Debug for AlgorithmParameters {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             Self::Absent => f.write_str("Absent"),
//             Self::Null => f.write_str("Null"),
//             Self::Built(_) => f.write_str("Built(..)"),
//             Self::Decoded(any) => f.debug_tuple("Decoded").field(any).finish(),
//         }
//     }
// }
//
// /// 演算法的 OID 加上它的參數。
// ///
// /// # 範例
// ///
// /// 要不要帶參數由演算法規定：rsaEncryption **必須**帶 NULL（RFC 3279 §2.2.1），
// /// Ed25519 與 ecdsa-with-SHA256 **必須**省略。少了 rsaEncryption 的 `05 00`
// /// 是常見的互通錯誤。
// ///
// /// 建構時參數直接放型別化的值；解碼時參數不解讀，要用時照 `algorithm` 決定型別：
// ///
// /// ```
// /// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions, EncodingType, DecodeInner};
// /// use tc_asn1_x509::{AlgorithmIdentifier, AlgorithmParameters};
// ///
// /// let alg = AlgorithmIdentifier::with_null("1.2.840.113549.1.1.1".parse()?); // rsaEncryption
// ///
// /// // 先問要多大，再配剛好的緩衝
// /// let mut out = vec![0_u8; alg.encoded_len(&EncodingOptions::new(EncodingType::Der))];
// /// alg.encode(&EncodingOptions::new(EncodingType::Der), &mut out)?;
// /// assert_eq!(
// ///     out,
// ///     [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00],
// /// );
// ///
// /// // 解回來：消耗整個緩衝
// /// let (used, decoded) = AlgorithmIdentifier::decode(&out, &DecodingOptions::default())?;
// /// assert_eq!(used, out.len());
// /// assert_eq!(decoded.algorithm().to_string(), "1.2.840.113549.1.1.1");
// ///
// /// // NULL 光看 tag 就認得，解碼直接給變體
// /// assert!(matches!(decoded.parameters(), AlgorithmParameters::Null));
// /// # Ok::<(), tc_asn1::Asn1Error>(())
// /// ```
// ///
// /// # 時間性質
// ///
// /// 變動時間。分支只依編碼結構；`algorithm` 與 `parameters` 都是公開值。
// #[derive(Debug)]
// pub struct AlgorithmIdentifier {
//     algorithm: Asn1Oid,
//     parameters: AlgorithmParameters,
// }
//
// impl AlgorithmIdentifier {
//     /// 沒有參數，例如 Ed25519。
//     pub fn new(algorithm: Asn1Oid) -> Self {
//         Self {
//             algorithm,
//             parameters: AlgorithmParameters::Absent,
//         }
//     }
//
//     /// 參數是 NULL：rsaEncryption 和所有 `*WithRSAEncryption` 的簽章演算法。
//     pub fn with_null(algorithm: Asn1Oid) -> Self {
//         Self {
//             algorithm,
//             parameters: AlgorithmParameters::Null,
//         }
//     }
//
//     /// 帶其他參數，例如 ecPublicKey 配曲線的 OID。
//     pub fn with_parameters(algorithm: Asn1Oid, parameters: impl Encode + 'static) -> Self {
//         Self {
//             algorithm,
//             parameters: AlgorithmParameters::Built(Box::new(parameters)),
//         }
//     }
//
//     /// 演算法的 OID。
//     pub fn algorithm(&self) -> &Asn1Oid {
//         &self.algorithm
//     }
//
//     /// 參數，三種狀態見 [`AlgorithmParameters`]。
//     pub fn parameters(&self) -> &AlgorithmParameters {
//         &self.parameters
//     }
//
//     /// 解進來、而且不是 NULL 的參數；其他情況回 `None`。
//     pub fn decoded_parameters(&self) -> Option<&Asn1Any> {
//         match &self.parameters {
//             AlgorithmParameters::Decoded(any) => Some(any),
//             _ => None,
//         }
//     }
// }
//
// impl<'a> tc_asn1::DecodeInner<'a> for AlgorithmIdentifier {
//     fn decode_inner(
//         buff: &'a [u8],
//         context: &mut tc_asn1::DecodingContext<'_>,
//     ) -> Result<(usize, Self), tc_asn1::Asn1Error> {
//         let element = tc_asn1::Asn1Ref::parse(buff, context)?;
//         if !element.is_constructed() {
//             return Err(tc_asn1::Asn1Error::UnexpectedTag);
//         }
//         let value = <Self as tc_asn1::DecodeContent<'a>>::decode_content(element.value(), context)?;
//         Ok((element.total_len(), value))
//     }
//     fn decode_inner_der(
//         buff: &'a [u8],
//         context: &mut tc_asn1::DecodingContext<'_>,
//     ) -> Result<(usize, Self), tc_asn1::Asn1Error> {
//         let element = tc_asn1::Asn1Ref::parse_der(buff, context)?;
//         if !element.is_constructed() {
//             return Err(tc_asn1::Asn1Error::UnexpectedTag);
//         }
//         let value =
//             <Self as tc_asn1::DecodeContent<'a>>::decode_content_der(element.value(), context)?;
//         Ok((element.total_len(), value))
//     }
// }
// impl<'a> tc_asn1::Decode<'a> for AlgorithmIdentifier {
//     fn decode(
//         buff: &'a [u8],
//         options: &tc_asn1::DecodingOptions,
//     ) -> Result<(usize, Self), tc_asn1::Asn1Error> {
//         <Self as tc_asn1::DecodeInner<'a>>::decode_inner(
//             buff,
//             &mut tc_asn1::DecodingContext::new(options),
//         )
//     }
// }
//
// impl<'a> DecodeContent<'a> for AlgorithmIdentifier {
//     /// 變動時間：分支只依編碼結構。
//     ///
//     /// 剛好兩個以內的欄位；第三個回 [`Asn1Error::TrailingData`]，
//     /// 少了 `algorithm` 回 [`Asn1Error::Truncated`]。
//     fn decode_content(
//         value: &'a [u8],
//         context: &mut DecodingContext<'_>,
//     ) -> Result<Self, Asn1Error> {
//         let mut fields = Fields::new(value, context)?;
//         let algorithm = fields.required(tc_asn1::tag::OBJECT_IDENTIFIER)?;
//         let parameters = match fields.peek()? {
//             None => AlgorithmParameters::Absent,
//             Some(field) if field.tag() == NULL => {
//                 fields.required::<Asn1Null>(NULL)?;
//                 AlgorithmParameters::Null
//             }
//             Some(_) => AlgorithmParameters::Decoded(Asn1Any::from(&fields.next()?)),
//         };
//         fields.finish()?;
//         Ok(Self {
//             algorithm,
//             parameters,
//         })
//     }
//
//     fn decode_content_der(
//         value: &'a [u8],
//         context: &mut DecodingContext<'_>,
//     ) -> Result<Self, Asn1Error> {
//         let mut fields = Fields::new(value, context)?;
//         let algorithm = fields.required_der(tc_asn1::tag::OBJECT_IDENTIFIER)?;
//         let parameters = match fields.peek()? {
//             None => AlgorithmParameters::Absent,
//             Some(field) if field.tag() == NULL => {
//                 fields.required_der::<Asn1Null>(NULL)?;
//                 AlgorithmParameters::Null
//             }
//             Some(_) => {
//                 let child = fields.next()?;
//                 AlgorithmParameters::Decoded(child.decode_as_der(fields.context())?)
//             }
//         };
//         fields.finish()?;
//         Ok(Self {
//             algorithm,
//             parameters,
//         })
//     }
// }
//
// impl SequenceFields for AlgorithmIdentifier {
//     /// 變動時間：分支只依編碼結構。
//     fn fields(&self, _: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
//         sink(&self.algorithm);
//         match &self.parameters {
//             AlgorithmParameters::Absent => {}
//             AlgorithmParameters::Null => sink(&Asn1Null),
//             AlgorithmParameters::Built(value) => sink(value.as_ref()),
//             AlgorithmParameters::Decoded(value) => sink(value),
//         }
//     }
// }
//
// tc_asn1::impl_sequence_encode!(AlgorithmIdentifier);
