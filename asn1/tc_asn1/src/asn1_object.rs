//! 具名結構與位元組之間的中間層。

pub mod asn1_boolean;
pub mod asn1_integer;
pub mod asn1_null;
pub mod asn1_set;

use crate::asn1_error::Asn1Error;
use crate::asn1_object::asn1_boolean::Asn1Boolean;
use crate::asn1_object::asn1_null::Asn1Null;
use crate::asn1_object::asn1_set::Asn1Set;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::tag::{self, Tag};
use crate::traits::{TryDecode, TryEncode};

/// 任何一個 ASN.1 值。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Asn1Object {
    /// `BOOLEAN`，universal 1。
    Boolean(Asn1Boolean),

    /// `NULL`，universal 5。
    Null(Asn1Null),

    /// `SET`，universal 17。
    Set(Asn1Set),
}

impl Asn1Object {
    /// 這個值的 tag。
    ///
    /// 解碼時用來分派，`SET` 的 DER 排序也拿它當第一個鍵。
    pub const fn tag(&self) -> Tag {
        match self {
            Self::Boolean(_) => Tag::BOOLEAN,
            Self::Null(_) => Tag::NULL,
            Self::Set(_) => Tag::SET,
        }
    }
}

impl TryEncode for Asn1Object {
    type Error = Asn1Error;

    /// 變動時間：轉給實際的型別。
    fn try_encode_len(&self, encoding_type: EncodingType) -> Result<usize, Self::Error> {
        match self {
            Self::Boolean(value) => value.try_encode_len(encoding_type),
            Self::Null(value) => value.try_encode_len(encoding_type),
            Self::Set(value) => value.try_encode_len(encoding_type),
        }
    }

    /// 變動時間：轉給實際的型別。
    fn try_encode(
        &self,
        encoding_type: EncodingType,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error> {
        match self {
            Self::Boolean(value) => value.try_encode(encoding_type, buff),
            Self::Null(value) => value.try_encode(encoding_type, buff),
            Self::Set(value) => value.try_encode(encoding_type, buff),
        }
    }
}

impl TryDecode for Asn1Object {
    type Error = Asn1Error;

    /// 變動時間：先看 tag 決定型別，再轉給它。
    ///
    /// 一層巢狀就是一次這個呼叫，所以深度預算在這裡消耗。
    fn try_decode(buff: &[u8], depth: Depth) -> Result<(usize, Self), Self::Error> {
        let depth = depth.descend()?;

        // 只看 tag，不消耗 —— 實際的型別會從頭再解一次表頭。
        let (_, decoded_tag) = tag::decode(buff)?;

        match decoded_tag {
            Tag::BOOLEAN => {
                let (consumed, value) = Asn1Boolean::try_decode(buff, depth)?;
                Ok((consumed, Self::Boolean(value)))
            }
            Tag::NULL => {
                let (consumed, value) = Asn1Null::try_decode(buff, depth)?;
                Ok((consumed, Self::Null(value)))
            }
            Tag::SET => {
                let (consumed, value) = Asn1Set::try_decode(buff, depth)?;
                Ok((consumed, Self::Set(value)))
            }
            _ => Err(Asn1Error::UnexpectedTag),
        }
    }
}
