// use crate::asn1_ref::{is_constructed_form, ChildCursor};
// use crate::{
//     Asn1Error, Asn1Ref, DecodeConstructed, DecodeContent, DecodeInner, DecodingContext,
//     DecodingOptions,
// };
// use crate::decoding_context::DepthScope;
// 
// pub struct Fields<'a, 'c, 'o> {
//     children: ChildCursor<'a>,
//     scope: DepthScope<'c, 'o>,
//     lookahead: Option<Asn1Ref<'a>>,
// }
// impl<'a, 'c, 'o> Fields<'a, 'c, 'o> {
//     pub fn new(value: &'a [u8], context: &'c mut DecodingContext) -> Result<Self, Asn1Error> {
//         context.options().check_content_len(value.len())?;
//         let children = crate::asn1_ref::ChildCursor::new(value, context.options());
//         Ok(Self {
//             children,
//             scope: context.enter()?,
//             lookahead: None,
//         })
//     }
//     pub fn options(&self) -> &'o DecodingOptions {
//         self.scope.options()
//     }
// 
//     pub fn context(&mut self) -> &mut DecodingContext {
//         self.scope.context()
//     }
// 
//     pub fn required<T: DecodeInner<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         if child.tag() != tag {
//             return Err(Asn1Error::UnexpectedTag);
//         }
//         child.decode_as(self.context())
//     }
// 
//     pub fn optional<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.required(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
//     /// 省略時採預設值；不拒絕 BER 明寫的預設值。變動時間：分支只依編碼結構。
//     pub fn default<T: DecodeInner>(&mut self, tag: &[u8], default: T) -> Result<T, Asn1Error> {
//         match self.optional(tag)? {
//             Some(value) => Ok(value),
//             None => Ok(default),
//         }
//     }
// 
//     pub fn explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         if child.tag() != tag || !child.is_constructed() {
//             return Err(Asn1Error::UnexpectedTag);
//         }
//         let mut inner = Fields::new(child.value(), self.context())?;
//         let value = inner.next()?.decode_as(inner.context())?;
//         inner.finish()?;
//         Ok(value)
//     }
//     /// 只有 tag 相符才取走 EXPLICIT 欄位。變動時間：分支只依編碼結構。
//     pub fn optional_explicit<T: DecodeInner>(
//         &mut self,
//         tag: &[u8],
//     ) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.explicit(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
//     /// 驗證替換後的 tag，直接按 T 的內容規則解碼；不增加額外包裝層。
//     /// The caller selects the content decoder; segmented strings use
//     /// [`Self::implicit_constructed`] instead.
//     /// 變動時間：分支只依編碼結構。
//     pub fn implicit<T: DecodeContent>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         if child.tag() == tag {
//             crate::decoding::content::<T>(child.value(), self.context())
//         } else {
//             Err(Asn1Error::UnexpectedTag)
//         }
//     }
// 
//     pub fn implicit_constructed<T: DecodeConstructed>(
//         &mut self,
//         tag: &[u8],
//     ) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         if !is_constructed_form(child.tag(), tag) {
//             return Err(Asn1Error::UnexpectedTag);
//         }
//         T::decode_constructed(child.value(), self.context())
//     }
//     /// Consume an IMPLICIT field with the exact tag selected by the schema;
//     /// otherwise leave it for the next reader.
//     /// Variable time: branches only on the encoding structure.
//     pub fn optional_implicit<T: DecodeContent>(
//         &mut self,
//         tag: &[u8],
//     ) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.implicit(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
// 
//     pub fn required_der<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         if child.tag() != tag {
//             return Err(Asn1Error::UnexpectedTag);
//         }
//         child.decode_as_der(self.context())
//     }
// 
//     /// Read this field using DER validation, including nested ASN.1 elements.
//     /// Variable time: public input only; no constant-time alternative is provided.
//     pub fn optional_der<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.required_der(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
// 
//     /// Read this field using DER validation, including nested ASN.1 elements.
//     /// Variable time: public input only; no constant-time alternative is provided.
//     pub fn default_der<T: DecodeInner + PartialEq>(
//         &mut self,
//         tag: &[u8],
//         default: T,
//     ) -> Result<T, Asn1Error> {
//         match self.optional_der(tag)? {
//             Some(value) if value == default => Err(Asn1Error::NotDer),
//             Some(value) => Ok(value),
//             None => Ok(default),
//         }
//     }
// 
//     /// Read this field using DER validation, including nested ASN.1 elements.
//     /// Variable time: public input only; no constant-time alternative is provided.
//     pub fn explicit_der<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         Asn1Ref::parse_der(child.raw(), self.context())?;
//         if child.tag() != tag || !child.is_constructed() {
//             return Err(Asn1Error::UnexpectedTag);
//         }
//         let mut inner = Fields::new(child.value(), self.context())?;
//         let value = inner.next()?.decode_as_der(inner.context())?;
//         inner.finish()?;
//         Ok(value)
//     }
// 
//     pub fn optional_explicit_der<T: DecodeInner>(
//         &mut self,
//         tag: &[u8],
//     ) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.explicit_der(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
// 
//     pub fn implicit_der<T: DecodeContent>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
//         let child = self.next()?;
//         Asn1Ref::parse_der(child.raw(), self.context())?;
//         if child.tag() == tag {
//             T::decode_content_der(child.value(), self.context())
//         } else {
//             Err(Asn1Error::UnexpectedTag)
//         }
//     }
// 
//     /// Read this field using DER validation, including nested ASN.1 elements.
//     /// Variable time: public input only; no constant-time alternative is provided.
//     pub fn optional_implicit_der<T: DecodeContent>(
//         &mut self,
//         tag: &[u8],
//     ) -> Result<Option<T>, Asn1Error> {
//         if self.peek()?.is_some_and(|field| field.tag() == tag) {
//             self.implicit_der(tag).map(Some)
//         } else {
//             Ok(None)
//         }
//     }
//     /// 偷看下一個欄位而不取走；解析失敗時呼叫端應立即返回錯誤。
//     /// 變動時間：分支只依編碼結構。
//     pub fn peek(&mut self) -> Result<Option<Asn1Ref<'a>>, Asn1Error> {
//         if self.lookahead.is_none() {
//             self.lookahead = self.children.next(self.scope.context()).transpose()?;
//         }
//         Ok(self.lookahead)
//     }
//     /// 取走下一個欄位；沒有欄位回傳 `Truncated`。變動時間：分支只依編碼結構。
//     #[allow(clippy::should_implement_trait)] // 工單的游標 API；缺欄位是錯誤，不是 Iterator 的 None。
//     pub fn next(&mut self) -> Result<Asn1Ref<'a>, Asn1Error> {
//         if let Some(child) = self.lookahead.take() {
//             Ok(child)
//         } else {
//             self.children
//                 .next(self.scope)
//                 .ok_or(Asn1Error::Truncated)?
//         }
//     }
//     /// 完成讀取，任何剩餘欄位（含損壞的尾端）都回傳 `TrailingData`。
//     /// 每個成功的解碼路徑都必須呼叫。變動時間：分支只依編碼結構。
//     pub fn finish(mut self) -> Result<(), Asn1Error> {
//         if self.lookahead.is_some() || self.children.next(self.scope).is_some() {
//             Err(Asn1Error::TrailingData)
//         } else {
//             Ok(())
//         }
//     }
// }
