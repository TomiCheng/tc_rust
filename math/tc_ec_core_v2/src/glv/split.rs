use tc_bigint::BigInt;

/// BC 的 `ScalarSplitParameters`：格基底 v1、v2，以及 g1、g2 的 `bits` 位定點近似。
#[derive(Clone, Debug)]
pub struct ScalarSplit {
    v1: [BigInt; 2],
    v2: [BigInt; 2],
    g1: BigInt,
    g2: BigInt,
    bits: u32,
}

impl ScalarSplit {
    /// The parameters in BC's order. Variable time; they are public.
    pub fn new(v1: [BigInt; 2], v2: [BigInt; 2], g1: BigInt, g2: BigInt, bits: u32) -> Self {
        Self {
            v1,
            v2,
            g1,
            g2,
            bits,
        }
    }

    /// BC `EndoUtilities.DecomposeScalar`: (a, b) with k = a + bλ mod n, each about half as
    /// long as n. Variable time: only for a public scalar.
    pub fn decompose(&self, k: &BigInt) -> (BigInt, BigInt) {
        let b1 = calculate_b(k, &self.g1, self.bits);
        let b2 = calculate_b(k, &self.g2, self.bits);
        let a = k - &(&(&b1 * &self.v1[0]) + &(&b2 * &self.v2[0]));
        let b = -(&(&b1 * &self.v1[1]) + &(&b2 * &self.v2[1]));
        (a, b)
    }
}

// BC `EndoUtilities.CalculateB`: k·g / 2^t, rounded to the nearest.
fn calculate_b(k: &BigInt, g: &BigInt, t: u32) -> BigInt {
    let negative = *g < BigInt::from(0u8);
    let product = k * &BigInt::from(g.clone().unsigned_abs());
    let extra = product.bit(t - 1);
    let mut b = &product >> t;
    if extra {
        b += 1u32;
    }
    if negative { -b } else { b }
}

#[cfg(test)]
mod tests {
    use super::ScalarSplit;
    use tc_bigint::BigInt;

    fn hex(text: &str) -> BigInt {
        let (negative, digits) = match text.strip_prefix('-') {
            Some(digits) => (true, digits),
            None => (false, text),
        };
        let value = digits.chars().fold(BigInt::from(0u8), |acc, digit| {
            (acc << 4) + BigInt::from(digit.to_digit(16).unwrap())
        });
        if negative { -value } else { value }
    }

    // BC's `CustomNamedCurves` secp256k1.
    fn secp256k1() -> ScalarSplit {
        ScalarSplit::new(
            [
                hex("3086d221a7d46bcde86c90e49284eb15"),
                hex("-e4437ed6010e88286f547fa90abfe4c3"),
            ],
            [
                hex("114ca50f7a8e2f3f657c1108d9d44cfd8"),
                hex("3086d221a7d46bcde86c90e49284eb15"),
            ],
            hex("3086d221a7d46bcde86c90e49284eb153dab"),
            hex("e4437ed6010e88286f547fa90abfe4c42212"),
            272,
        )
    }

    // k = a + bλ mod n, with a and b of at most 129 bits against n's 256.
    #[test]
    fn a_secp256k1_scalar_splits_into_two_halves() {
        let n = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let lambda = hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
        let split = secp256k1();
        let mut k = BigInt::from(1u8);
        for _ in 0..40 {
            let (a, b) = split.decompose(&k);
            let rebuilt = (&a + &(&b * &lambda) - &k) % &n;
            assert!(rebuilt == BigInt::from(0u8), "k = {k:?}");
            assert!(a.bits() <= 129 && b.bits() <= 129, "k = {k:?}");
            k = (&k * &hex("9e3779b97f4a7c15f39cc0605cedc835")) % &n + BigInt::from(1u8);
        }
        let (a, b) = split.decompose(&(&n - BigInt::from(1u8)));
        assert!(a.bits() <= 129 && b.bits() <= 129);
    }
}
