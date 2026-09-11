//! 讀入的契約。

use crate::asn1_ref::Asn1Ref;
use crate::depth::Depth;
use crate::error::Asn1Error;

/// 只解內容，不碰表頭。IMPLICIT 標記過的欄位走這裡。
pub trait TryDecodeContent<'a>: Sized {
    /// 沒有被重新標記時，這個型別的識別位元組。
    const TAG: &'static [u8];

    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error>;
}

/// 解一個完整的 TLV。由 [`TryDecodeContent`] 自動得到。
pub trait TryDecode<'a>: Sized {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error>;
}

impl<'a, T: TryDecodeContent<'a>> TryDecode<'a> for T {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, depth)?;
        Ok((element.total_len(), element.decode_as(depth)?))
    }
}
