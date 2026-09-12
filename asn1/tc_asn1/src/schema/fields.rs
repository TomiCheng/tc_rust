//! 具名 constructed 值的解碼游標。
use crate::asn1_ref::is_constructed_form;
use crate::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeConstructed, DecodeContent, DecodingOptions,
};

/// 依 schema 順序讀取欄位；成功路徑最後必須呼叫 [`Self::finish`]。
/// 忘記呼叫不會有編譯器警告，但可能錯誤接受多餘欄位。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Integer, DecodingOptions, Fields};
/// let mut fields = Fields::new(&[2, 1, 5], DecodingOptions::default())?;
/// assert!(!fields.default(&[1], Asn1Boolean(false))?.0);
/// let number: Asn1Integer = fields.required(&[2])?;
/// assert_eq!(i64::try_from(&number)?, 5);
/// fields.finish()?;
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Fields<'a> {
    children: Children<'a>,
    options: DecodingOptions,
    lookahead: Option<Asn1Ref<'a>>,
}
impl<'a> Fields<'a> {
    /// 進入 constructed 的內容，消耗一層深度。變動時間：分支只依編碼結構。
    pub fn new(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        let options = options.descend()?;
        Ok(Self {
            children: Children::new(value, options),
            options,
            lookahead: None,
        })
    }
    /// Return the options for child fields, including the remaining depth.
    /// Constant time: copies the stored configuration.
    pub fn options(&self) -> DecodingOptions {
        self.options
    }
    /// 讀取必要欄位，支援 CHOICE 與 ANY；沒有欄位回傳 `Truncated`。
    /// The schema supplies the exact identifier, including its constructed bit.
    /// For an unrestricted ANY or CHOICE, use [`Self::next`] and [`Asn1Ref::decode_as`].
    /// 解碼器必須消耗完整的子 TLV。變動時間：分支只依編碼結構。
    pub fn required<T: Decode<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if child.tag() != tag {
            return Err(Asn1Error::UnexpectedTag);
        }
        let (used, value) = T::try_decode(child.raw(), self.options)?;
        if used != child.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
    /// Consume the exact identifier selected by the schema, or leave the field
    /// for the next reader. Pass a constructed identifier to accept that form.
    /// Variable time: branches only on the encoding structure.
    pub fn optional<T: Decode<'a>>(&mut self, tag: &[u8]) -> Result<Option<T>, Asn1Error> {
        if self.peek()?.is_some_and(|field| field.tag() == tag) {
            self.required(tag).map(Some)
        } else {
            Ok(None)
        }
    }
    /// 省略時採預設值；不拒絕 BER 明寫的預設值。變動時間：分支只依編碼結構。
    pub fn default<T: Decode<'a>>(&mut self, tag: &[u8], default: T) -> Result<T, Asn1Error> {
        Ok(self.optional(tag)?.unwrap_or(default))
    }
    /// 讀取 EXPLICIT constructed 包裝，內部必須剛好一個完整 TLV。
    /// 包裝另外消耗一層深度。變動時間：分支只依編碼結構。
    pub fn explicit<T: Decode<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if child.tag() != tag || !child.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut inner = Self::new(child.value(), self.options)?;
        let value = inner.next()?.decode_as(inner.options())?;
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
    /// The caller selects the content decoder; segmented strings use
    /// [`Self::implicit_constructed`] instead.
    /// 變動時間：分支只依編碼結構。
    pub fn implicit<T: DecodeContent<'a>>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let child = self.next()?;
        if child.tag() == tag {
            T::try_decode_content(child.value(), self.options)
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
    /// use tc_asn1::{Asn1OctetString, DecodingOptions, Fields};
    /// // [0] IMPLICIT OCTET STRING 的 BER 分段形式。
    /// let options = DecodingOptions::new(tc_asn1::Depth::new(2), 4096, 64);
    /// let mut fields = Fields::new(&[0xa0, 3, 4, 1, 0xaa], options)?;
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
        T::try_decode_constructed(child.value(), self.options)
    }
    /// Consume an IMPLICIT field with the exact tag selected by the schema;
    /// otherwise leave it for the next reader.
    /// Variable time: branches only on the encoding structure.
    pub fn optional_implicit<T: DecodeContent<'a>>(
        &mut self,
        tag: &[u8],
    ) -> Result<Option<T>, Asn1Error> {
        if self.peek()?.is_some_and(|field| field.tag() == tag) {
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
            Fields::new(&[], DecodingOptions::default())
                .unwrap()
                .required::<Asn1Null>(&[5]),
            Err(Asn1Error::Truncated)
        );
        assert_eq!(
            Fields::new(&[1, 1, 0], DecodingOptions::default())
                .unwrap()
                .required::<Asn1Null>(&[5]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn optional_fields_preserve_a_nonmatching_lookahead_for_the_next_reader() {
        let mut fields = Fields::new(&[5, 0], DecodingOptions::default()).unwrap();
        assert_eq!(fields.optional::<Asn1Boolean>(&[1]), Ok(None));
        assert_eq!(fields.peek().unwrap().unwrap().tag(), &[5]);
        assert_eq!(fields.required::<Asn1Null>(&[5]), Ok(Asn1Null));
        assert_eq!(fields.finish(), Ok(()));
    }
    #[test]
    fn default_fields_accept_explicit_values_and_supply_omitted_values() {
        assert!(
            Fields::new(&[1, 1, 255], DecodingOptions::default())
                .unwrap()
                .default(&[1], Asn1Boolean(false))
                .unwrap()
                .0
        );
        assert!(
            !Fields::new(&[], DecodingOptions::default())
                .unwrap()
                .default(&[1], Asn1Boolean(false))
                .unwrap()
                .0
        );
        assert!(
            !Fields::new(&[1, 1, 0], DecodingOptions::default())
                .unwrap()
                .default(&[1], Asn1Boolean(false))
                .unwrap()
                .0
        );
    }
    #[test]
    fn explicit_fields_require_one_inner_tlv_and_the_requested_constructed_tag() {
        let n: Asn1Integer = Fields::new(&[0xA0, 3, 2, 1, 2], DecodingOptions::default())
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
                Fields::new(bytes, DecodingOptions::default())
                    .unwrap()
                    .explicit::<Asn1Integer>(&[0xA0]),
                Err(error)
            );
        }
        assert_eq!(
            Fields::new(&[0x80, 3, 2, 1, 2], DecodingOptions::default())
                .unwrap()
                .explicit::<Asn1Integer>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn implicit_fields_replace_tags_without_adding_a_depth_layer() {
        let mut fields = Fields::new(
            &[0x80, 1, 255],
            DecodingOptions::new(crate::Depth::new(1), 16 * 1024 * 1024, 65_536),
        )
        .unwrap();
        assert_eq!(
            fields.implicit::<Asn1Boolean>(&[0x80]),
            Ok(Asn1Boolean(true))
        );
        assert_eq!(fields.finish(), Ok(()));
        assert_eq!(
            Fields::new(&[0x81, 1, 255], DecodingOptions::default())
                .unwrap()
                .implicit::<Asn1Boolean>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn optional_tagged_fields_leave_nonmatching_values_and_decode_matching_values() {
        let mut fields =
            Fields::new(&[0xA0, 2, 5, 0, 0x80, 1, 255], DecodingOptions::default()).unwrap();
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
        let mut fields = Fields::new(&[5, 0], DecodingOptions::default()).unwrap();
        fields.peek().unwrap();
        assert_eq!(fields.finish(), Err(Asn1Error::TrailingData));
        assert_eq!(
            Fields::new(&[5], DecodingOptions::default())
                .unwrap()
                .finish(),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(
            Fields::new(&[], DecodingOptions::default())
                .unwrap()
                .finish(),
            Ok(())
        );
    }
    #[test]
    fn constructed_values_and_explicit_wrappers_each_consume_depth() {
        assert!(matches!(
            Fields::new(
                &[],
                DecodingOptions::new(crate::Depth::new(0), 16 * 1024 * 1024, 65_536)
            ),
            Err(Asn1Error::DepthExceeded)
        ));
        let bytes = [0xA0, 2, 5, 0];
        assert_eq!(
            Fields::new(
                &bytes,
                DecodingOptions::new(crate::Depth::new(1), 16 * 1024 * 1024, 65_536)
            )
            .unwrap()
            .explicit::<Asn1Null>(&[0xA0]),
            Err(Asn1Error::DepthExceeded)
        );
        assert_eq!(
            Fields::new(
                &bytes,
                DecodingOptions::new(crate::Depth::new(2), 16 * 1024 * 1024, 65_536)
            )
            .unwrap()
            .explicit::<Asn1Null>(&[0xA0]),
            Ok(Asn1Null)
        );
        assert!(matches!(
            Fields::new(
                &[0x30, 0],
                DecodingOptions::new(crate::Depth::new(1), 16 * 1024 * 1024, 65_536)
            )
            .unwrap()
            .required::<Asn1SequenceOf<Asn1Null>>(&[0x30]),
            Err(Asn1Error::DepthExceeded)
        ));
    }
    #[test]
    fn any_and_choice_decoders_can_read_required_and_explicit_fields() {
        struct Choice(Asn1Boolean);
        impl<'a> Decode<'a> for Choice {
            fn try_decode(
                bytes: &'a [u8],
                depth: DecodingOptions,
            ) -> Result<(usize, Self), Asn1Error> {
                Asn1Boolean::try_decode(bytes, depth).map(|(n, v)| (n, Self(v)))
            }
        }
        let mut fields =
            Fields::new(&[1, 1, 255, 0xA0, 2, 5, 0], DecodingOptions::default()).unwrap();
        assert!(fields.required::<Choice>(&[1]).unwrap().0.0);
        let any = fields.explicit::<Asn1Any>(&[0xA0]).unwrap();
        assert_eq!(any.as_ref().tag(), &[5]);
        fields.finish().unwrap();
    }
    #[test]
    fn optional_and_default_fields_accept_schema_selected_constructed_octets() {
        use crate::Asn1OctetString;
        let input = [0x24, 3, 4, 1, 0xaa];
        let mut fields = Fields::new(&input, DecodingOptions::default()).unwrap();
        assert_eq!(
            fields.optional::<Asn1OctetString>(&[0x24]),
            Ok(Some(Asn1OctetString::new(&[0xaa])))
        );
        fields.finish().unwrap();
        let mut fields = Fields::new(&input, DecodingOptions::default()).unwrap();
        assert_eq!(
            fields.default(&[0x24], Asn1OctetString::new(&[])),
            Ok(Asn1OctetString::new(&[0xaa]))
        );
        fields.finish().unwrap();
    }

    #[test]
    fn the_schema_selects_constructed_implicit_fields_without_extra_wrapper_depth() {
        use crate::Asn1OctetString;
        let input = [0xa0, 3, 4, 1, 0xaa];
        let mut fields = Fields::new(
            &input,
            DecodingOptions::new(crate::Depth::new(2), 16 * 1024 * 1024, 65_536),
        )
        .unwrap();
        assert_eq!(
            fields.implicit_constructed::<Asn1OctetString>(&[0x80]),
            Ok(Asn1OctetString::new(&[0xaa]))
        );
        fields.finish().unwrap();
        let mut fields = Fields::new(
            &input,
            DecodingOptions::new(crate::Depth::new(2), 16 * 1024 * 1024, 65_536),
        )
        .unwrap();
        assert_eq!(
            fields.optional::<Asn1OctetString>(&[0xa0]),
            Ok(Some(Asn1OctetString::new(&[0xaa])))
        );
        fields.finish().unwrap();
        assert_eq!(
            Fields::new(
                &input,
                DecodingOptions::new(crate::Depth::new(1), 16 * 1024 * 1024, 65_536)
            )
            .unwrap()
            .implicit_constructed::<Asn1OctetString>(&[0x80]),
            Err(Asn1Error::DepthExceeded)
        );
        let high = [0xbf, 0x81, 0, 3, 4, 1, 0xaa];
        assert_eq!(
            Fields::new(&high, DecodingOptions::default())
                .unwrap()
                .optional::<Asn1OctetString>(&[0xbf, 0x81, 0]),
            Ok(Some(Asn1OctetString::new(&[0xaa])))
        );
        let mut fields = Fields::new(&input, DecodingOptions::default()).unwrap();
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
            let mut fields = Fields::new(
                input,
                DecodingOptions::new(crate::Depth::new(depth), 16 * 1024 * 1024, 65_536),
            )
            .unwrap();
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
        let mut fields = Fields::new(
            &[0xa0, 4, 3, 2, 7, 0x80],
            DecodingOptions::new(crate::Depth::new(2), 16 * 1024 * 1024, 65_536),
        )
        .unwrap();
        assert_eq!(
            fields
                .implicit_constructed::<Asn1BitString>(&[0x80])
                .unwrap(),
            Asn1BitString::from_bits(&[0x80], 1),
        );
        fields.finish().unwrap();
    }

    #[test]
    fn unschema_selected_constructed_forms_are_rejected_or_left_for_the_next_field() {
        let input = [0x21, 3, 1, 1, 0xff];
        assert_eq!(
            Asn1Boolean::try_decode(&input, DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let mut fields = Fields::new(&input, DecodingOptions::default()).unwrap();
        assert_eq!(fields.optional::<Asn1Boolean>(&[1]), Ok(None));
        assert_eq!(
            fields.default(&[1], Asn1Boolean(false)),
            Ok(Asn1Boolean(false))
        );
        assert_eq!(fields.peek().unwrap().unwrap().raw(), input);
        fields.required::<Asn1Any>(&[0x21]).unwrap();
        fields.finish().unwrap();

        let input = [0xa0, 3, 1, 1, 0xff];
        let mut fields = Fields::new(&input, DecodingOptions::default()).unwrap();
        assert_eq!(fields.optional_implicit::<Asn1Boolean>(&[0x80]), Ok(None));
        assert_eq!(fields.peek().unwrap().unwrap().raw(), input);
        assert_eq!(
            fields.implicit::<Asn1Boolean>(&[0x80]),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
