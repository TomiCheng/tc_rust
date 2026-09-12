//! 具名 constructed 值的解碼游標。
use crate::asn1_ref::is_constructed_form;
use crate::{Asn1Error, Asn1Ref, Children, Decode, DecodeConstructed, DecodeContent, Depth};

/// 依 schema 順序讀取欄位；成功路徑最後必須呼叫 [`Self::finish`]。
/// 忘記呼叫不會有編譯器警告，但可能錯誤接受多餘欄位。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Integer, Depth, Fields};
/// let mut fields = Fields::new(&[2, 1, 5], Depth::DEFAULT)?;
/// assert!(!fields.default(Asn1Boolean(false))?.0);
/// let number: Asn1Integer = fields.required()?;
/// assert_eq!(i64::try_from(&number)?, 5);
/// fields.finish()?;
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Fields<'a> {
    children: Children<'a>,
    depth: Depth,
    lookahead: Option<Asn1Ref<'a>>,
}
impl<'a> Fields<'a> {
    /// 進入 constructed 的內容，消耗一層深度。變動時間：分支只依編碼結構。
    pub fn new(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        Ok(Self {
            children: Children::new(value, depth),
            depth,
            lookahead: None,
        })
    }
    /// 取得子欄位使用的深度。變動時間契約：分支只依編碼結構。
    pub fn depth(&self) -> Depth {
        self.depth
    }
    /// 讀取必要欄位，支援 CHOICE 與 ANY；沒有欄位回傳 `Truncated`。
    /// 解碼器必須消耗完整的子 TLV。變動時間：分支只依編碼結構。
    pub fn required<T: Decode<'a>>(&mut self) -> Result<T, Asn1Error> {
        let child = self.next()?;
        let (used, value) = T::try_decode(child.raw(), self.depth)?;
        if used != child.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
    /// tag 相同或是其 constructed 形式才取走欄位，否則保留給後續欄位。
    /// constructed 形式交給一般解碼入口時回傳 `UnexpectedTag`。變動時間：分支只依編碼結構。
    pub fn optional<T: DecodeContent<'a>>(&mut self) -> Result<Option<T>, Asn1Error> {
        if self
            .peek()?
            .is_some_and(|field| field.tag() == T::TAG || is_constructed_form(field.tag(), T::TAG))
        {
            self.required().map(Some)
        } else {
            Ok(None)
        }
    }
    /// 省略時採預設值；不拒絕 BER 明寫的預設值。變動時間：分支只依編碼結構。
    /// 嚴格 DER 檢查由重編碼後的往返比較負責。
    pub fn default<T: DecodeContent<'a>>(&mut self, default: T) -> Result<T, Asn1Error> {
        Ok(self.optional()?.unwrap_or(default))
    }
    /// 讀取 EXPLICIT constructed 包裝，內部必須剛好一個完整 TLV。
    /// 包裝另外消耗一層深度。變動時間：分支只依編碼結構。
    pub fn explicit<T: Decode<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if child.tag() != tag || !child.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut inner = Self::new(child.value(), self.depth)?;
        let value = inner.required()?;
        inner.finish()?;
        Ok(value)
    }
    /// 只有 tag 相符才取走 EXPLICIT 欄位。變動時間：分支只依編碼結構。
    pub fn optional_explicit<T: Decode<'a>>(&mut self, tag: &[u8]) -> Result<Option<T>, Asn1Error> {
        if self.peek()?.is_some_and(|field| field.tag() == tag) {
            self.explicit(tag).map(Some)
        } else {
            Ok(None)
        }
    }
    /// 驗證替換後的 tag，直接按 T 的內容規則解碼；不增加額外包裝層。
    /// tag 必須完全相符；分段字串請使用 [`Self::implicit_constructed`]。
    /// 變動時間：分支只依編碼結構。
    pub fn implicit<T: DecodeContent<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if child.tag() == tag {
            T::try_decode_content(child.value(), self.depth)
        } else {
            Err(Asn1Error::UnexpectedTag)
        }
    }
    /// 讀取 IMPLICIT 分段字串；傳入替換後的 primitive tag，只接受其 constructed 形式。
    /// 內容交由 `DecodeConstructed` 的入口解碼，不增加額外包裝層。
    /// 變動時間：分支只依編碼結構，只能用於公開值；沒有常數時間替代方法。
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1OctetString, Depth, Fields};
    /// // [0] IMPLICIT OCTET STRING 的 BER 分段形式。
    /// let mut fields = Fields::new(&[0xa0, 3, 4, 1, 0xaa], Depth::new(2))?;
    /// let value: Asn1OctetString = fields.implicit_constructed(&[0x80])?;
    /// assert_eq!(value.as_bytes(), &[0xaa]);
    /// fields.finish()?;
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn implicit_constructed<T: DecodeConstructed<'a>>(
        &mut self,
        tag: &[u8],
    ) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if !is_constructed_form(child.tag(), tag) {
            return Err(Asn1Error::UnexpectedTag);
        }
        T::try_decode_constructed(child.value(), self.depth)
    }
    /// tag 相同或是其 constructed 形式才取走 IMPLICIT 欄位。
    /// constructed 形式交給 [`Self::implicit`] 時會回傳 `UnexpectedTag`。
    /// 變動時間：分支只依編碼結構。
    pub fn optional_implicit<T: DecodeContent<'a>>(
        &mut self,
        tag: &[u8],
    ) -> Result<Option<T>, Asn1Error> {
        if self
            .peek()?
            .is_some_and(|field| field.tag() == tag || is_constructed_form(field.tag(), tag))
        {
            self.implicit(tag).map(Some)
        } else {
            Ok(None)
        }
    }
    /// 偷看下一個欄位而不取走；解析失敗時呼叫端應立即返回錯誤。
    /// 變動時間：分支只依編碼結構。
    pub fn peek(&mut self) -> Result<Option<Asn1Ref<'a>>, Asn1Error> {
        if self.lookahead.is_none() {
            self.lookahead = self.children.next().transpose()?;
        }
        Ok(self.lookahead)
    }
    /// 取走下一個欄位；沒有欄位回傳 `Truncated`。變動時間：分支只依編碼結構。
    #[allow(clippy::should_implement_trait)] // 工單的游標 API；缺欄位是錯誤，不是 Iterator 的 None。
    pub fn next(&mut self) -> Result<Asn1Ref<'a>, Asn1Error> {
        if let Some(child) = self.lookahead.take() {
            Ok(child)
        } else {
            self.children.next().ok_or(Asn1Error::Truncated)?
        }
    }
    /// 完成讀取，任何剩餘欄位（含損壞的尾端）都回傳 `TrailingData`。
    /// 每個成功的解碼路徑都必須呼叫。變動時間：分支只依編碼結構。
    pub fn finish(mut self) -> Result<(), Asn1Error> {
        if self.lookahead.is_some() || self.children.next().is_some() {
            Err(Asn1Error::TrailingData)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Any, Asn1Boolean, Asn1Integer, Asn1Null, Asn1SequenceOf};
    #[test]
    fn required_fields_reject_missing_values_and_unexpected_tags() {
        assert_eq!(
            Fields::new(&[], Depth::DEFAULT)
                .unwrap()
                .required::<Asn1Null>(),
            Err(Asn1Error::Truncated)
        );
        assert_eq!(
            Fields::new(&[1, 1, 0], Depth::DEFAULT)
                .unwrap()
                .required::<Asn1Null>(),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn optional_fields_preserve_a_nonmatching_lookahead_for_the_next_reader() {
        let mut fields = Fields::new(&[5, 0], Depth::DEFAULT).unwrap();
        assert_eq!(fields.optional::<Asn1Boolean>(), Ok(None));
        assert_eq!(fields.peek().unwrap().unwrap().tag(), &[5]);
        assert_eq!(fields.required::<Asn1Null>(), Ok(Asn1Null));
        assert_eq!(fields.finish(), Ok(()));
    }
    #[test]
    fn default_fields_accept_explicit_values_and_supply_omitted_values() {
        assert!(
            Fields::new(&[1, 1, 255], Depth::DEFAULT)
                .unwrap()
                .default(Asn1Boolean(false))
                .unwrap()
                .0
        );
        assert!(
            !Fields::new(&[], Depth::DEFAULT)
                .unwrap()
                .default(Asn1Boolean(false))
                .unwrap()
                .0
        );
        assert!(
            !Fields::new(&[1, 1, 0], Depth::DEFAULT)
                .unwrap()
                .default(Asn1Boolean(false))
                .unwrap()
                .0
        );
    }
    #[test]
    fn explicit_fields_require_one_inner_tlv_and_the_requested_constructed_tag() {
        let n: Asn1Integer = Fields::new(&[0xA0, 3, 2, 1, 2], Depth::DEFAULT)
            .unwrap()
            .explicit(&[0xA0])
            .unwrap();
        assert_eq!(i64::try_from(&n), Ok(2));
        for (bytes, error) in [
            (&[0xA0, 0][..], Asn1Error::Truncated),
            (&[0xA0, 6, 2, 1, 2, 2, 1, 3], Asn1Error::TrailingData),
            (&[0xA1, 3, 2, 1, 2], Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(
                Fields::new(bytes, Depth::DEFAULT)
                    .unwrap()
                    .explicit::<Asn1Integer>(&[0xA0]),
                Err(error)
            );
        }
        assert_eq!(
            Fields::new(&[0x80, 3, 2, 1, 2], Depth::DEFAULT)
                .unwrap()
                .explicit::<Asn1Integer>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn implicit_fields_replace_tags_without_adding_a_depth_layer() {
        let mut fields = Fields::new(&[0x80, 1, 255], Depth::new(1)).unwrap();
        assert_eq!(
            fields.implicit::<Asn1Boolean>(&[0x80]),
            Ok(Asn1Boolean(true))
        );
        assert_eq!(fields.finish(), Ok(()));
        assert_eq!(
            Fields::new(&[0x81, 1, 255], Depth::DEFAULT)
                .unwrap()
                .implicit::<Asn1Boolean>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn optional_tagged_fields_leave_nonmatching_values_and_decode_matching_values() {
        let mut fields = Fields::new(&[0xA0, 2, 5, 0, 0x80, 1, 255], Depth::DEFAULT).unwrap();
        assert_eq!(fields.optional_implicit::<Asn1Boolean>(&[0x81]), Ok(None));
        assert_eq!(fields.optional_explicit::<Asn1Null>(&[0xA1]), Ok(None));
        assert_eq!(
            fields.optional_explicit::<Asn1Null>(&[0xA0]),
            Ok(Some(Asn1Null))
        );
        assert_eq!(
            fields.optional_implicit::<Asn1Boolean>(&[0x80]),
            Ok(Some(Asn1Boolean(true)))
        );
        assert_eq!(fields.optional_explicit::<Asn1Null>(&[0xA0]), Ok(None));
        assert_eq!(fields.finish(), Ok(()));
    }
    #[test]
    fn finishing_rejects_remaining_fields_including_buffered_or_malformed_tails() {
        let mut fields = Fields::new(&[5, 0], Depth::DEFAULT).unwrap();
        fields.peek().unwrap();
        assert_eq!(fields.finish(), Err(Asn1Error::TrailingData));
        assert_eq!(
            Fields::new(&[5], Depth::DEFAULT).unwrap().finish(),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(Fields::new(&[], Depth::DEFAULT).unwrap().finish(), Ok(()));
    }
    #[test]
    fn constructed_values_and_explicit_wrappers_each_consume_depth() {
        assert!(matches!(
            Fields::new(&[], Depth::new(0)),
            Err(Asn1Error::DepthExceeded)
        ));
        let bytes = [0xA0, 2, 5, 0];
        assert_eq!(
            Fields::new(&bytes, Depth::new(1))
                .unwrap()
                .explicit::<Asn1Null>(&[0xA0]),
            Err(Asn1Error::DepthExceeded)
        );
        assert_eq!(
            Fields::new(&bytes, Depth::new(2))
                .unwrap()
                .explicit::<Asn1Null>(&[0xA0]),
            Ok(Asn1Null)
        );
        assert!(matches!(
            Fields::new(&[0x30, 0], Depth::new(1))
                .unwrap()
                .required::<Asn1SequenceOf<Asn1Null>>(),
            Err(Asn1Error::DepthExceeded)
        ));
    }
    #[test]
    fn any_and_choice_decoders_can_read_required_and_explicit_fields() {
        struct Choice(Asn1Boolean);
        impl<'a> Decode<'a> for Choice {
            fn try_decode(bytes: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
                Asn1Boolean::try_decode(bytes, depth).map(|(n, v)| (n, Self(v)))
            }
        }
        let mut fields = Fields::new(&[1, 1, 255, 0xA0, 2, 5, 0], Depth::DEFAULT).unwrap();
        assert!(fields.required::<Choice>().unwrap().0.0);
        let any = fields.explicit::<Asn1Any>(&[0xA0]).unwrap();
        assert_eq!(any.as_ref().tag(), &[5]);
        fields.finish().unwrap();
    }
    #[test]
    fn optional_and_default_fields_reject_constructed_octets_without_explicit_dispatch() {
        use crate::Asn1OctetString;
        let input = [0x24, 3, 4, 1, 0xaa];
        let mut fields = Fields::new(&input, Depth::DEFAULT).unwrap();
        assert_eq!(
            fields.optional::<Asn1OctetString>(),
            Err(Asn1Error::UnexpectedTag)
        );
        fields.finish().unwrap();
        let mut fields = Fields::new(&input, Depth::DEFAULT).unwrap();
        assert_eq!(
            fields.default(Asn1OctetString::new(&[])),
            Err(Asn1Error::UnexpectedTag)
        );
        fields.finish().unwrap();
    }

    #[test]
    fn implicit_fields_reject_constructed_forms_instead_of_decoding_components() {
        use crate::Asn1OctetString;
        let input = [0xa0, 3, 4, 1, 0xaa];
        let mut fields = Fields::new(&input, Depth::new(2)).unwrap();
        assert_eq!(
            fields.implicit::<Asn1OctetString>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
        fields.finish().unwrap();
        let mut fields = Fields::new(&input, Depth::new(2)).unwrap();
        assert_eq!(
            fields.optional_implicit::<Asn1OctetString>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
        fields.finish().unwrap();
        assert_eq!(
            Fields::new(&input, Depth::new(1))
                .unwrap()
                .implicit::<Asn1OctetString>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
        let high = [0xbf, 0x81, 0, 3, 4, 1, 0xaa];
        assert_eq!(
            Fields::new(&high, Depth::DEFAULT)
                .unwrap()
                .optional_implicit::<Asn1OctetString>(&[0x9f, 0x81, 0]),
            Err(Asn1Error::UnexpectedTag)
        );
        let mut fields = Fields::new(&input, Depth::DEFAULT).unwrap();
        assert_eq!(
            fields.optional_implicit::<Asn1OctetString>(&[0x81]),
            Ok(None)
        );
        assert_eq!(fields.peek().unwrap().unwrap().tag(), &[0xa0]);
    }

    #[test]
    fn implicit_constructed_fields_validate_tags_and_depth() {
        use crate::{Asn1BitString, Asn1OctetString};
        use alloc::vec;
        for (input, tag, depth, expected) in [
            (&[0xa0, 3, 4, 1, 0xaa][..], &[0x80][..], 2, Ok(vec![0xaa])),
            (
                &[0xbf, 0x81, 0, 3, 4, 1, 0xaa],
                &[0x9f, 0x81, 0],
                2,
                Ok(vec![0xaa]),
            ),
            (
                &[0xa0, 3, 4, 1, 0xaa],
                &[0x80],
                1,
                Err(Asn1Error::DepthExceeded),
            ),
            (&[0x80, 1, 0xaa], &[0x80], 2, Err(Asn1Error::UnexpectedTag)),
            (&[0xa1, 0], &[0x80], 2, Err(Asn1Error::UnexpectedTag)),
            (&[0xa0, 0], &[0xa0], 2, Err(Asn1Error::UnexpectedTag)),
            (&[0xa0, 2, 5, 0], &[0x80], 2, Err(Asn1Error::UnexpectedTag)),
            (&[], &[0x80], 2, Err(Asn1Error::Truncated)),
        ] {
            let mut fields = Fields::new(input, Depth::new(depth)).unwrap();
            assert_eq!(
                fields
                    .implicit_constructed::<Asn1OctetString>(tag)
                    .map(|value| value.as_bytes().to_vec()),
                expected,
            );
            if expected.is_ok() {
                fields.finish().unwrap();
            }
        }
        let mut fields = Fields::new(&[0xa0, 4, 3, 2, 7, 0x80], Depth::new(2)).unwrap();
        assert_eq!(
            fields
                .implicit_constructed::<Asn1BitString>(&[0x80])
                .unwrap(),
            Asn1BitString::from_bits(&[0x80], 1),
        );
        fields.finish().unwrap();
    }

    #[test]
    fn optional_constructed_forms_of_unsupported_types_are_errors_instead_of_absent_fields() {
        let input = [0x21, 3, 1, 1, 0xff];
        assert_eq!(
            Fields::new(&input, Depth::DEFAULT)
                .unwrap()
                .optional::<Asn1Boolean>(),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Fields::new(&input, Depth::DEFAULT)
                .unwrap()
                .default(Asn1Boolean(false)),
            Err(Asn1Error::UnexpectedTag)
        );
        let input = [0xa0, 3, 1, 1, 0xff];
        assert_eq!(
            Fields::new(&input, Depth::DEFAULT)
                .unwrap()
                .optional_implicit::<Asn1Boolean>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
