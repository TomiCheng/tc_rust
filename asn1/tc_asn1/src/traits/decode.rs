//! 讀入的契約。

use crate::asn1_ref::Asn1Ref;
use crate::depth::Depth;
use crate::error::Asn1Error;
use crate::{Encode, EncodingType};

/// 只解內容，不碰表頭。IMPLICIT 標記過的欄位走這裡。
pub trait TryDecodeContent<'a>: Sized {
    /// 沒有被重新標記時，這個型別的識別位元組。
    const TAG: &'static [u8];

    /// 變動時間：分支只依編碼結構。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error>;
    /// 同號碼的 BER constructed 形式；內容是一串成分 TLV，預設不支援。
    /// 變動時間：分支只依編碼結構。
    fn try_decode_constructed(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let _ = (value, depth);
        Err(Asn1Error::UnexpectedTag)
    }
}

/// 解一個完整的 TLV。由 [`TryDecodeContent`] 自動得到。
pub trait TryDecode<'a>: Sized {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error>;

    /// 剛好一個 TLV，後面不准有東西。變動時間：分支只依編碼結構。
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Error, Asn1Null, Depth, TryDecode};
    /// assert_eq!(Asn1Null::try_decode_exact(&[5, 0], Depth::DEFAULT), Ok(Asn1Null));
    /// assert_eq!(Asn1Null::try_decode_exact(&[5, 0, 5, 0], Depth::DEFAULT),
    ///     Err(Asn1Error::TrailingData));
    /// ```
    fn try_decode_exact(buff: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let (used, value) = Self::try_decode(buff, depth)?;
        if used != buff.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }

    /// 以 DER 往返比較檢查已解讀部分，重編不同時回傳 [`Asn1Error::NotDer`]。
    /// 變動時間：分支只依編碼結構，最後比較公開的編碼位元組。
    ///
    /// [`crate::Asn1Any`] 與 [`crate::Asn1Object::Unknown`] 保真，原樣重送的
    /// 部分無法查出 DER 違規；例如下例的 constructed 字元字串仍會通過。
    /// [`crate::Asn1Object::Set`] 缺少 schema，也無法保證 SET OF CHOICE 的排序。
    /// 呼叫端需選擇符合 schema 的型別；這不是對任意 ASN.1 的完整 DER 驗證器。
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Asn1Error, Asn1Object, Depth, TryDecode};
    /// assert_eq!(Asn1Boolean::try_decode_der(&[1, 1, 1], Depth::DEFAULT),
    ///     Err(Asn1Error::NotDer));
    /// assert_eq!(Asn1Boolean::try_decode_der(&[1, 1, 255], Depth::DEFAULT),
    ///     Ok(Asn1Boolean(true)));
    /// // Unknown 內容不解讀，不能靠往返比較驗證其中的 DER。
    /// assert!(Asn1Object::try_decode_der(&[0x30, 3, 0x2c, 1, 0x41], Depth::DEFAULT).is_ok());
    /// ```
    fn try_decode_der(buff: &'a [u8], depth: Depth) -> Result<Self, Asn1Error>
    where
        Self: Encode,
    {
        let value = Self::try_decode_exact(buff, depth)?;
        if value.encode_to_vec(EncodingType::Der)? != buff {
            return Err(Asn1Error::NotDer);
        }
        Ok(value)
    }
}

impl<'a, T: TryDecodeContent<'a>> TryDecode<'a> for T {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, depth)?;
        Ok((element.total_len(), element.decode_as(depth)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Asn1Any, Asn1Boolean, Asn1Integer, Asn1Null, Asn1Object, Asn1OctetString, Asn1SetOf,
    };

    #[test]
    fn exact_decode_rejects_trailing_data_and_preserves_decode_errors() {
        assert_eq!(
            Asn1Null::try_decode_exact(&[5, 0], Depth::DEFAULT),
            Ok(Asn1Null)
        );
        assert_eq!(
            Asn1Null::try_decode_exact(&[5, 0, 5, 0], Depth::DEFAULT),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(
            Asn1Null::try_decode_exact(&[5], Depth::DEFAULT),
            Err(Asn1Error::Truncated)
        );
    }

    #[test]
    fn der_decode_rejects_noncanonical_booleans_lengths_sets_and_constructed_strings() {
        assert_eq!(
            Asn1Boolean::try_decode_der(&[1, 1, 1], Depth::DEFAULT),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            Asn1Boolean::try_decode_der(&[1, 1, 255], Depth::DEFAULT),
            Ok(Asn1Boolean(true))
        );
        assert_eq!(
            Asn1Null::try_decode_der(&[5, 0x81, 0], Depth::DEFAULT),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            Asn1Null::try_decode_der(&[5, 0, 5, 0], Depth::DEFAULT),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(
            Asn1SetOf::<Asn1Integer>::try_decode_der(&[0x31, 6, 2, 1, 5, 2, 1, 3], Depth::DEFAULT),
            Err(Asn1Error::NotDer)
        );
        assert!(
            Asn1SetOf::<Asn1Integer>::try_decode_der(&[0x31, 6, 2, 1, 3, 2, 1, 5], Depth::DEFAULT)
                .is_ok()
        );
        assert_eq!(
            Asn1OctetString::try_decode_der(&[0x24, 3, 4, 1, 0xaa], Depth::DEFAULT),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            Asn1Object::try_decode_der(&[0x24, 3, 4, 1, 0xaa], Depth::DEFAULT),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            alloc::string::ToString::to_string(&Asn1Error::NotDer),
            "encoding is not DER"
        );
    }

    #[test]
    fn der_round_trip_checks_cannot_validate_opaque_encodings() {
        let input = [0x30, 3, 0x2c, 1, 0x41];
        let value = Asn1Object::try_decode_der(&input, Depth::DEFAULT).unwrap();
        assert!(matches!(
            &value.as_sequence().unwrap()[0],
            Asn1Object::Unknown(_)
        ));
        let input = [1, 0x81, 1, 1];
        assert!(Asn1Any::try_decode_der(&input, Depth::DEFAULT).is_ok());
    }

    #[test]
    fn der_decode_propagates_encoding_errors_instead_of_replacing_them_with_not_der() {
        let input = [
            0x31, 12, 0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0,
        ];
        assert_eq!(
            Asn1Object::try_decode_der(&input, Depth::DEFAULT),
            Err(Asn1Error::TagOverflow)
        );
    }
}
