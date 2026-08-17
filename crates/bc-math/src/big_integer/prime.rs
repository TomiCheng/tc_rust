//! Primality testing and random prime generation.
//!
//! Split into a submodule so the `rand` dependency stays isolated here and the
//! parent `big_integer.rs` remains pure arithmetic. As a descendant module this
//! can reach the parent's private items (`sign`, `magnitude`, `BigInteger::new`).

use super::BigInteger;

impl BigInteger {
    // 質數相關方法將寫在這裡：is_probable_prime / with_probable_prime /
    // next_probable_prime，以及 Miller-Rabin 的私有 helper。
}

#[cfg(test)]
mod tests {
    use super::BigInteger;

    #[test]
    fn prime_module_reaches_private_fields() {
        // 冒煙測試：證明子模組能直接存取父模組的私有欄位（子孫可見）。
        let n = BigInteger::from_u32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }
}
