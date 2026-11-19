use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

use crate::CmsError;

// bytes 裡剛好一個結構，後面沒有東西
pub(crate) fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, CmsError> {
    let (used, value) = T::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    Ok(value)
}

// 以 DER 重新編碼後照 U 解讀，例如把結構轉成 Asn1Object 或 Asn1Any
pub(crate) fn convert<T: Encode, U: Decode>(value: &T) -> Result<U, CmsError> {
    decode_all(&value.encode_to_vec(&EncodingOptions::DER)?)
}

// DER 的長度八位元組，接在 out 後面
pub(crate) fn length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend(&bytes[skip..]);
}

// eContent 的 OCTET STRING，BER 分段的（constructed，0x24）也接受，各段依序串起來；tc_asn1 的
// Asn1OctetString 只讀單一段
pub(crate) fn octets(any: &tc_asn1::Asn1Any) -> Result<Vec<u8>, CmsError> {
    let mut context = tc_asn1::DecodingContext::new(DecodingOptions::default());
    let mut out = Vec::new();
    collect(&any.as_ref(), &mut context, &mut out)?;
    Ok(out)
}

fn collect(
    element: &tc_asn1::Asn1Ref<'_>,
    context: &mut tc_asn1::DecodingContext,
    out: &mut Vec<u8>,
) -> Result<(), CmsError> {
    match element.tag() {
        [0x04] => out.extend_from_slice(element.value()),
        [0x24] => {
            let mut children = element.children(context)?;
            while children.peek().is_some() {
                let child: tc_asn1::Asn1Any = children.get()?;
                collect(&child.as_ref(), children.context(), out)?;
            }
        }
        _ => return Err(Asn1Error::UnexpectedTag.into()),
    }
    Ok(())
}
