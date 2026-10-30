//! 測試共用的參數。
#![allow(dead_code)]

use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_dh_key::DhParameters;

/// RFC 3526 的 2048 位元 MODP 群組（group 14），取自 BC 的 `DHStandardGroups`：
/// p 是安全質數，g = 2，q = (p − 1) / 2。
pub fn group14() -> DhParameters {
    let p = from_hex(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
         020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
         4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
         ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
         98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
         9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b\
         e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718\
         3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
    );
    let q = PaddedBigUint::from(BigUint::from(p.clone()) >> 1);
    DhParameters::new(p, PaddedBigUint::from(2u8)).with_q(q)
}

/// 十六進位轉成 [`PaddedBigUint`]。
pub fn from_hex(hex: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    PaddedBigUint::from(BigUint::from_be(&bytes).unwrap())
}

/// 小整數轉成 [`PaddedBigUint`]。
pub fn n(value: u64) -> PaddedBigUint {
    PaddedBigUint::from(value)
}
