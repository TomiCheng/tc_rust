//! 測試共用的參數與轉換。
#![allow(dead_code)]

use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_elgamal::ElGamalParameters;

/// RFC 3526 的 2048 位元 MODP 群組（group 14）的 p 與 g = 2，取自 BC 的
/// `DHStandardGroups`。
pub fn group14() -> ElGamalParameters {
    ElGamalParameters::new(
        from_hex(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
        020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
        4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
        ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
        98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
        9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b\
        e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718\
        3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        ),
        PaddedBigUint::from(2u8),
    )
}

/// 十六進位轉成 [`PaddedBigUint`]。
pub fn from_hex(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from(BigUint::from_be(&decode(hex)).unwrap())
}

/// 十六進位轉成位元組。
pub fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 轉成 [`BigUint`] 以便比較。
pub fn big(value: &PaddedBigUint) -> BigUint {
    BigUint::from(value.clone())
}
