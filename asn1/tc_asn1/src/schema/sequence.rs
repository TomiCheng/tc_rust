//! 欄位只列一次的具名 SEQUENCE 編碼。
use crate::{Encode, EncodingType};

/// 列出要編碼的欄位；OPTIONAL／DEFAULT 的條件只需寫在這裡。
/// sink 會同步使用借用值，可以傳入臨時的標記包裝。
/// 同一組規則下，多次呼叫必須產生相同順序、內容與長度。
/// 此契約不代表只執行一次：長度計算與寫入各自會列舉欄位。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Integer, Encode, EncodingType, SequenceFields, impl_sequence_encode};
/// struct Pair { flag: Asn1Boolean, count: Asn1Integer }
/// impl SequenceFields for Pair {
///     fn fields(&self, _: EncodingType, sink: &mut dyn FnMut(&dyn Encode)) {
///         sink(&self.flag);
///         sink(&self.count);
///     }
/// }
/// impl_sequence_encode!(Pair);
/// let value = Pair { flag: Asn1Boolean(true), count: 5_u8.into() };
/// let mut out = [0; 8];
/// value.encode(EncodingType::Der, &mut out)?;
/// assert_eq!(out, [0x30, 6, 1, 1, 0xFF, 2, 1, 5]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub trait SequenceFields {
    /// 按 schema 順序同步提供欄位。變動時間：分支只依編碼結構。
    fn fields(&self, rules: EncodingType, sink: &mut dyn FnMut(&dyn Encode));
}

/// 由 [`SequenceFields`] 產生 [`Encode`]；預設 SEQUENCE，可給第二個參數換 tag。
/// 不使用 blanket impl，以免與 `Box<T>: Encode` 的實作重疊。
///
/// # Examples
/// ```
/// use tc_asn1::{Encode, EncodingType, SequenceFields, impl_sequence_encode};
/// struct EmptyApplication;
/// impl SequenceFields for EmptyApplication {
///     fn fields(&self, _: EncodingType, _: &mut dyn FnMut(&dyn Encode)) {}
/// }
/// impl_sequence_encode!(EmptyApplication, &[0x60]);
/// let mut out = [0; 2];
/// EmptyApplication.encode(EncodingType::Der, &mut out)?;
/// assert_eq!(out, [0x60, 0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[macro_export]
macro_rules! impl_sequence_encode {
    ($t:ty) => {
        $crate::impl_sequence_encode!($t, $crate::tag::SEQUENCE);
    };
    ($t:ty, $tag:expr) => {
        impl $crate::Encode for $t {
            /// 回傳結構的 tag。變動時間契約：分支只依編碼結構。
            fn tag(&self) -> &[u8] {
                $tag
            }
            /// 累加欄位的完整 TLV 長度。變動時間：分支只依編碼結構。
            fn content_len(&self, rules: $crate::EncodingType) -> usize {
                let mut total = 0;
                $crate::SequenceFields::fields(self, rules, &mut |field| {
                    total += field.encoded_len(rules)
                });
                total
            }
            /// 依序寫入欄位，回傳第一個編碼錯誤。變動時間：分支只依編碼結構。
            fn encode_content(
                &self,
                rules: $crate::EncodingType,
                out: &mut [u8],
            ) -> ::core::result::Result<usize, $crate::Asn1Error> {
                let mut at = 0;
                let mut error = ::core::option::Option::None;
                $crate::SequenceFields::fields(self, rules, &mut |field| {
                    if error.is_none() {
                        match field.encode(rules, &mut out[at..]) {
                            ::core::result::Result::Ok(n) => at += n,
                            ::core::result::Result::Err(e) => {
                                error = ::core::option::Option::Some(e)
                            }
                        }
                    }
                });
                error.map_or(::core::result::Result::Ok(at), ::core::result::Result::Err)
            }
        }
    };
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Boolean, Asn1Error, Asn1Integer, Explicit, Implicit};
    struct Pair(Asn1Boolean, Asn1Integer);
    impl SequenceFields for Pair {
        fn fields(&self, _: EncodingType, sink: &mut dyn FnMut(&dyn Encode)) {
            sink(&self.0);
            sink(&self.1);
        }
    }
    crate::impl_sequence_encode!(Pair);
    #[test]
    fn the_sequence_macro_encodes_two_fields_in_schema_order() {
        let value = Pair(Asn1Boolean(true), 5_u8.into());
        let mut out = [0; 8];
        assert_eq!(value.encode(EncodingType::Der, &mut out), Ok(8));
        assert_eq!(out, [0x30, 6, 1, 1, 255, 2, 1, 5]);
    }
    struct Tagged;
    impl SequenceFields for Tagged {
        fn fields(&self, rules: EncodingType, sink: &mut dyn FnMut(&dyn Encode)) {
            if rules == EncodingType::Ber {
                sink(&Implicit::new(&[0x80], &Asn1Boolean(false)));
            }
            sink(&Explicit::new(&[0xA0], &Asn1Boolean(true)));
        }
    }
    crate::impl_sequence_encode!(Tagged, &[0x60]);
    #[test]
    fn custom_tags_temporary_wrappers_and_rule_dependent_fields_work_together() {
        for (rules, expected) in [
            (EncodingType::Der, &[0x60, 5, 0xA0, 3, 1, 1, 255][..]),
            (
                EncodingType::Ber,
                &[0x60, 8, 0x80, 1, 0, 0xA0, 3, 1, 1, 255],
            ),
        ] {
            let mut out = alloc::vec![0; Tagged.encoded_len(rules)];
            Tagged.encode(rules, &mut out).unwrap();
            assert_eq!(out, expected);
        }
    }
    #[test]
    fn the_first_encoding_error_prevents_later_fields_from_being_written() {
        struct Fail;
        impl Encode for Fail {
            fn tag(&self) -> &[u8] {
                &[5]
            }
            fn content_len(&self, _: EncodingType) -> usize {
                0
            }
            fn encode_content(&self, _: EncodingType, _: &mut [u8]) -> Result<usize, Asn1Error> {
                Err(Asn1Error::MalformedValue)
            }
        }
        struct FailedSequence;
        impl SequenceFields for FailedSequence {
            fn fields(&self, _: EncodingType, sink: &mut dyn FnMut(&dyn Encode)) {
                sink(&Fail);
                sink(&Asn1Boolean(true));
            }
        }
        crate::impl_sequence_encode!(FailedSequence);
        let mut out = [0xAA; 5];
        assert_eq!(
            FailedSequence.encode_content(EncodingType::Der, &mut out),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(&out[2..], &[0xAA; 3]);
    }
}
