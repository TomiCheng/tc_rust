use alloc::vec::Vec;

use crate::{EcdsaError, EcdsaScalar};

/// 以定長 `r || s` 編碼簽章，各分量左補零到群階的位元組長度。
pub fn encode_plain<S: EcdsaScalar>(n: &S, r: &S, s: &S) -> Vec<u8> {
    let length = n.bit_length().div_ceil(8);
    let mut output = r.to_be_bytes_padded(length);
    output.extend_from_slice(&s.to_be_bytes_padded(length));
    output
}

/// 解碼定長 `r || s`，並驗證兩個分量都位於 `[1, n - 1]`。
pub fn decode_plain<S: EcdsaScalar>(n: &S, input: &[u8]) -> Result<(S, S), EcdsaError> {
    let length = n.bit_length().div_ceil(8);
    if input.len() != length * 2 {
        return Err(EcdsaError::InvalidEncodingLength);
    }
    let r = S::from_be_bytes(&input[..length]).ok_or(EcdsaError::ScalarOutOfRange)?;
    let s = S::from_be_bytes(&input[length..]).ok_or(EcdsaError::ScalarOutOfRange)?;
    if r.is_zero() || s.is_zero() || r >= *n || s >= *n {
        return Err(EcdsaError::InvalidSignatureValue);
    }
    Ok((r, s))
}
