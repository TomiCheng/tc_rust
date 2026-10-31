use super::{check, magnitude};
use crate::{DsaEncoding, DsaEncodingError};
use alloc::vec;
use alloc::vec::Vec;
use tc_asn1::{Asn1Integer, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// BC 的 `StandardDsaEncoding`：DER 的 SEQUENCE { INTEGER r, INTEGER s }，X9.62 與 X.509 的
/// 格式。解碼只接受 DER，同 BC 以重新編碼比對。
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardDsaEncoding;

/// DER 的 SEQUENCE { r, s }。變動時間：只能用於公開值。
fn der(r: &PaddedBigUint, s: &PaddedBigUint) -> Result<Vec<u8>, DsaEncodingError> {
    Asn1SequenceOf::new(vec![
        Asn1Integer::from_unsigned_bytes(&magnitude(r)),
        Asn1Integer::from_unsigned_bytes(&magnitude(s)),
    ])
    .encode_to_vec(&EncodingOptions::DER)
    .map_err(|_| DsaEncodingError::Malformed)
}

/// 內容長 `content` 位元組的 DER 編碼總長。變動時間：只能用於公開值。
fn encoded_length(content: usize) -> usize {
    let length_octets = if content < 0x80 {
        1
    } else {
        1 + (usize::BITS - content.leading_zeros()).div_ceil(8) as usize
    };
    1 + length_octets + content
}

/// INTEGER 的值：不得為負。變動時間：只能用於公開值。
fn value(integer: &Asn1Integer) -> Result<PaddedBigUint, DsaEncodingError> {
    let bytes = integer
        .as_unsigned_bytes()
        .map_err(|_| DsaEncodingError::ValueOutOfRange)?;
    let Ok(value) = PaddedBigUint::from_be(bytes);
    Ok(value)
}

impl DsaEncoding for StandardDsaEncoding {
    /// BC 的 `GetMaxEncodingSize`：兩個與 n 一樣長的 INTEGER 組成的 SEQUENCE。變動時間：
    /// 只能用於公開值。
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize {
        let n = magnitude(order);
        let content = n.len().max(1) + usize::from(n.first().is_some_and(|byte| byte & 0x80 != 0));
        encoded_length(2 * encoded_length(content))
    }

    /// r 與 s 要小於 n。變動時間：只能用於公開值。
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError> {
        check(order, r)?;
        check(order, s)?;
        let encoding = der(r, s)?;
        output
            .get_mut(..encoding.len())
            .ok_or(DsaEncodingError::OutputTooShort)?
            .copy_from_slice(&encoding);
        Ok(encoding.len())
    }

    /// 恰好兩個 INTEGER、沒有多餘的位元組、是 DER，值都在 `[0, n)` 裡。變動時間：只能用於
    /// 公開值。
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError> {
        let (used, sequence) =
            Asn1SequenceOf::<Asn1Integer>::decode(encoding, &DecodingOptions::default())
                .map_err(|_| DsaEncodingError::Malformed)?;
        let [r, s] = sequence.elements() else {
            return Err(DsaEncodingError::Malformed);
        };
        if used != encoding.len() {
            return Err(DsaEncodingError::Malformed);
        }
        let (r, s) = (value(r)?, value(s)?);
        check(order, &r)?;
        check(order, &s)?;
        if der(&r, &s)? != encoding {
            return Err(DsaEncodingError::Malformed);
        }
        Ok((r, s))
    }
}
