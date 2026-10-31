use crate::Sm2Curve;
use alloc::vec;
use alloc::vec::Vec;
use tc_digest::Digest;
use tc_ec_core::{FieldElement, Point};
use tc_zeroize::Zeroizing;

// BC 的 `CheckUserID`：ID 的位元數要放得進 16 位元的 ENTL。
pub(crate) const MAX_USER_ID_LENGTH: usize = 8192;

/// BC 在沒有 `ParametersWithID` 時的使用者 ID："1234567812345678"。
pub(crate) const DEFAULT_USER_ID: &[u8] = b"1234567812345678";

/// BC 的 `GetZ`：H(ENTL ‖ ID ‖ a ‖ b ‖ x_G ‖ y_G ‖ x_P ‖ y_P)，ENTL 是 ID 的位元數的兩個
/// 大端序位元組。變動時間：只處理公開的值。
pub(crate) fn z<C: Sm2Curve, D: Digest + Clone>(
    digest: &D,
    user_id: &[u8],
    g: &C::Point,
    point: &C::Point,
    field_length: usize,
) -> Vec<u8> {
    let curve = point.curve();
    let size = digest.digest_size();
    let mut digest = digest.clone();
    digest.reset();
    let bits = (user_id.len() * 8) as u16;
    digest.update(&bits.to_be_bytes());
    digest.update(user_id);
    for element in [curve.a(), curve.b()] {
        let mut bytes = vec![0u8; field_length];
        element.encode_to(&mut bytes);
        digest.update(&bytes);
    }
    for p in [g, point] {
        digest.update(&coordinate(p.x(), field_length));
        digest.update(&coordinate(p.y(), field_length));
    }
    let mut z = vec![0u8; size];
    digest.do_final(&mut z);
    z
}

/// 有限點的一個座標，編成 `field_length` 位元組。對座標是常數時間。
pub(crate) fn coordinate<F: FieldElement>(
    element: Option<F>,
    field_length: usize,
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; field_length]);
    element.expect("the point is finite").encode_to(&mut bytes);
    bytes
}
