use super::{check, magnitude};
use crate::{DsaEncoding, DsaEncodingError};
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// BC 的 `PlainDsaEncoding`：r ‖ s，各補成 n 的位元組數的大端序，例如 BSI TR-03111 與 JWS
/// 的格式。
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainDsaEncoding;

impl DsaEncoding for PlainDsaEncoding {
    /// n 的位元組數的兩倍。變動時間：只能用於公開值。
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize {
        magnitude(order).len() * 2
    }

    /// r 與 s 要小於 n，`output` 要放得下兩個值。變動時間：只能用於公開值。
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError> {
        check(order, r)?;
        check(order, s)?;
        let length = magnitude(order).len();
        let output = output
            .get_mut(..length * 2)
            .ok_or(DsaEncodingError::OutputTooShort)?;
        output.fill(0);
        for (half, value) in output.chunks_mut(length).zip([r, s]) {
            let bytes = magnitude(value);
            half[length - bytes.len()..].copy_from_slice(&bytes);
        }
        Ok(length * 2)
    }

    /// 長度要恰好是 n 的位元組數的兩倍，兩個值都要小於 n。變動時間：只能用於公開值。
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError> {
        let length = magnitude(order).len();
        if encoding.len() != length * 2 {
            return Err(DsaEncodingError::Malformed);
        }
        let (r, s) = encoding.split_at(length);
        let Ok(r) = PaddedBigUint::from_be(r);
        let Ok(s) = PaddedBigUint::from_be(s);
        check(order, &r)?;
        check(order, &s)?;
        Ok((r, s))
    }
}
