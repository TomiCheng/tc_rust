use super::FpNamedCurve;
use super::hex::hex;

/// SEC 2 secp112r2, broken. The cofactor is 4, so the group has points of order 2 and
/// the complete formulas of [`FpCtCurve`] hold only in the subgroup of `G`: a point
/// outside it may give a wrong result.
pub const SECP112R2: FpNamedCurve<14> = FpNamedCurve {
    p: hex("db7c2abf62e35e668076bead208b"),
    a: hex("6127c24c05f38a0aaaf65c0ef02c"),
    b: hex("51def1815db5ed74fcc34c85d709"),
    order: hex("36df0aafd8b8d7597ca10520d04b"),
    cofactor: 4,
    gx: hex("4ba30ab5e892b4e1649dd0928643"),
    gy: hex("adcd46f5882e3747def36e956e97"),
    glv: None,
};
