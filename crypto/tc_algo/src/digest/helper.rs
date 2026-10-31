use tc_asn1::Asn1Oid;

use super::Algorithm;
use crate::AlgoError;

pub fn calculate(algorithm: Algorithm, input: &[u8]) -> Vec<u8> {
    todo!()
}

pub fn calculate_by_name(name: &str, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    todo!()
}

pub fn calculate_by_oid(oid: &Asn1Oid, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    todo!()
}

/// 寫到 `output` 的開頭並回傳寫了幾個 byte；`output` 比 digest 短時 panic。
pub fn calculate_into(algorithm: Algorithm, input: &[u8], output: &mut [u8]) -> usize {
    todo!()
}

/// 寫到 `output` 的開頭並回傳寫了幾個 byte；`output` 比 digest 短時 panic。
pub fn calculate_by_name_into(
    name: &str,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AlgoError> {
    todo!()
}

/// 寫到 `output` 的開頭並回傳寫了幾個 byte；`output` 比 digest 短時 panic。
pub fn calculate_by_oid_into(
    oid: &Asn1Oid,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AlgoError> {
    todo!()
}
