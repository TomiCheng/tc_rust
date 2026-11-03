//! 每條曲線都自洽，且 BC 給的基點編碼解得出同一個 G。

use tc_bigint::PaddedBigUint;
use tc_brainpool_curves::*;
use tc_ec_core::Point;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼，要解出同一個 G
fn check_fp<const N: usize>(named: &BrainpoolNamedCurve<N>, cofactor: u32, encoded: &str) {
    let field = named.field();
    let ct_curve = named.ct_curve(&field);
    let var_curve = named.var_curve(&field);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity() && h.multiply(n).is_infinity());
    assert_eq!(ct_curve.cofactor(), Some(&PaddedBigUint::from(cofactor)));
    assert_eq!(ct_curve.decode_point(&hex(encoded)), Ok(g.clone()));
    assert_eq!(g.twice().encode(true), h.twice().encode(true));
}

#[test]
fn brainpool_p160r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P160R1,
        1,
        "04bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc31667cb477a1a8ec338f94741669c976316da6321",
    );
}

#[test]
fn brainpool_p160t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P160T1,
        1,
        "04b199b13b9b34efc1397e64baeb05acc265ff2378add6718b7c7c1961f0991b842443772152c9e0ad",
    );
}

#[test]
fn brainpool_p192r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P192R1,
        1,
        "04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
    );
}

#[test]
fn brainpool_p192t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P192T1,
        1,
        "043ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9",
    );
}

#[test]
fn brainpool_p224r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P224R1,
        1,
        "040d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
    );
}

#[test]
fn brainpool_p224t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P224T1,
        1,
        "046ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d5800374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c",
    );
}

#[test]
fn brainpool_p256r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P256R1,
        1,
        "048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
    );
}

#[test]
fn brainpool_p256t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P256T1,
        1,
        "04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be",
    );
}

#[test]
fn brainpool_p320r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P320R1,
        1,
        "0443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
    );
}

#[test]
fn brainpool_p320t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P320T1,
        1,
        "04925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed5263ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3",
    );
}

#[test]
fn brainpool_p384r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P384R1,
        1,
        "041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
    );
}

#[test]
fn brainpool_p384t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P384T1,
        1,
        "0418de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928",
    );
}

#[test]
fn brainpool_p512r1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P512R1,
        1,
        "0481aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8227dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
    );
}

#[test]
fn brainpool_p512t1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &BRAINPOOL_P512T1,
        1,
        "04640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332",
    );
}
