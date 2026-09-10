//! X448 — RFC 7748 Diffie-Hellman over Curve448.
//!
//! 這個模組使用 16-limb radix-2²⁸ 欄位與 Montgomery ladder。固定基點目前
//! 也走同一條 ladder；等 Ed448 固定基點核心加入後，只需替換
//! [`scalar_mult_base`] 的內部實作，公開 API 不會改變。

use super::x448_field::Fe448;
use rand_core::CryptoRng;
use tc_constant_time::Choice;

/// 常數時間：X448 公開鍵、共享秘密與 u 座標的位元組長度，為 56。
///
/// 這是編譯期公開常數，讀取不涉及秘密值。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let alice_private: [u8; x448::SCALAR_SIZE] = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let alice_public: [u8; x448::POINT_SIZE] = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::generate_public_key(&alice_private), alice_public);
/// ```
pub const POINT_SIZE: usize = 56;
/// 常數時間：X448 純量與私鑰的位元組長度，為 56。
///
/// 這是編譯期公開常數，讀取不涉及秘密值。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let alice_private: [u8; x448::SCALAR_SIZE] = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let alice_public: [u8; x448::POINT_SIZE] = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::generate_public_key(&alice_private), alice_public);
/// ```
pub const SCALAR_SIZE: usize = 56;

/// RFC 7748 定義的 X448 基點 `u = 5`。
const BASE_POINT: [u8; POINT_SIZE] = {
    let mut point = [0_u8; POINT_SIZE];
    point[0] = 5;
    point
};

/// Curve448 Montgomery coefficient `A = 156326`。
const C_A: u32 = 156326;
/// Montgomery ladder 常數 `(A + 2) / 4 = 39082`。
const C_A24: u32 = (C_A + 2) / 4;

const _: () = assert!(C_A24 == 39082);

/// 常數時間：依 RFC 7748 §5 夾制私鑰，只對固定位置做位元遮罩。
///
/// 清除最低兩位，並設定最高位。
/// 即使呼叫端傳入未夾制的純量，[`scalar_mult`] 也會在解碼時套用同樣規則。
/// 這個入口讓呼叫端能先將私鑰調整成夾制後的儲存格式。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
/// 夾制改變儲存位元組，但不改變純量乘法結果。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let mut private = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// x448::clamp_private_key(&mut private);
/// assert_eq!(private[0], 0x98);
/// assert_eq!(private[55], 0xeb);
/// let expected_public = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::generate_public_key(&private), expected_public);
/// ```
pub fn clamp_private_key(private_key: &mut [u8; SCALAR_SIZE]) {
    private_key[0] &= 0xFC;
    private_key[SCALAR_SIZE - 1] |= 0x80;
}

/// 變動時間（取決於 RNG）：從呼叫端的密碼學安全 RNG 產生 X448 私鑰。
///
/// 本函式固定取得 56 個位元組，再以常數時間的 [`clamp_private_key`] 夾制；
/// 不自行取得系統熵，也不能替任意 RNG 保證執行時間。亂數來源由呼叫端管理。
///
/// # Examples
///
/// 此範例只編譯，不執行 RNG；回傳值已符合 RFC 7748 §5 的夾制規則。
///
/// ```no_run
/// use tc_rfc7748::x448;
///
/// use rand_core::CryptoRng;
///
/// // 將應用程式已建立的 RNG 傳入；此處不提供示範用偽亂數產生器。
/// fn new_private_key(rng: &mut impl CryptoRng) -> [u8; x448::SCALAR_SIZE] {
///     let key = x448::generate_private_key(rng);
///     assert_eq!(key[0] & 3, 0);
///     assert_eq!(key[55] & 0x80, 0x80);
///     key
/// }
/// ```
pub fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; SCALAR_SIZE] {
    let mut private_key = [0_u8; SCALAR_SIZE];
    rng.fill_bytes(&mut private_key);
    clamp_private_key(&mut private_key);
    private_key
}

/// 常數時間：X448 由私鑰產生公開鍵。
///
/// 固定基點 `u = 5` 直接呼叫 [`scalar_mult`] 的固定圈數 ladder；
/// 條件交換使用 `cswap` 遮罩，最後的 `invert` 固定處理公開指數 `p - 2` 的 448 個位元；
/// 乘法步驟只由這個固定指數決定，不依秘密值分支。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let alice_private: [u8; x448::SCALAR_SIZE] = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let alice_public: [u8; x448::POINT_SIZE] = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::generate_public_key(&alice_private), alice_public);
/// ```
pub fn generate_public_key(private_key: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult_base(private_key)
}

/// 常數時間（末端僅揭露是否全零）：計算 X448 Diffie-Hellman 共享秘密。
///
/// 回傳 `None` 代表結果全零，也就是對方送入低階點。檢查會掃過完整輸出，
/// 不會在第一個非零 byte 提前結束。
///
/// [`scalar_mult`] 的 ladder 圈數固定，交換使用 `cswap` 遮罩。
/// 最後的 `invert` 固定處理公開指數 `p - 2` 的 448 個位元；
/// 乘法步驟只由這個固定指數決定，不依秘密值分支。
///
/// 末端的 `Some`／`None` 會揭露全零判定，這是本 API 刻意回報的拒絕條件。
/// 呼叫端收到 `None` 必須拒絕協議，不能用 `unwrap_or_default()` 把它換成全零秘密。
/// 需要金鑰衍生時，應將有效結果交給上層協議指定的 KDF。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
/// 先檢查有效協議，再示範低階點被拒絕。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let alice_private = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let bob_public = [
///     0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5,
///     0xbc, 0xfc, 0x0b, 0x59, 0x9b, 0x6f, 0xec, 0xcf,
///     0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4,
///     0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72,
///     0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c,
///     0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
///     0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09,
/// ];
/// let expected_shared = [
///     0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95,
///     0xec, 0x1c, 0x16, 0xa9, 0x4a, 0x0f, 0x74, 0xd1,
///     0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52,
///     0x28, 0x1d, 0x28, 0x2b, 0xb6, 0x0c, 0x0b, 0x56,
///     0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36,
///     0x52, 0x1c, 0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a,
///     0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
/// ];
/// assert_eq!(
///     x448::calculate_agreement(&alice_private, &bob_public),
///     Some(expected_shared),
/// );
///
/// // 對方送入低階點 u = 0：必須拒絕，不可取預設的全零陣列。
/// let low_order_point = [0; x448::POINT_SIZE];
/// let rejected = x448::calculate_agreement(&alice_private, &low_order_point);
/// assert!(rejected.is_none());
/// ```
pub fn calculate_agreement(
    private_key: &[u8; SCALAR_SIZE],
    peer_public_key: &[u8; POINT_SIZE],
) -> Option<[u8; POINT_SIZE]> {
    let agreement = scalar_mult(private_key, peer_public_key);
    let mut nonzero = 0_u8;
    for byte in agreement {
        nonzero |= byte;
    }
    if nonzero == 0 { None } else { Some(agreement) }
}

fn point_double(x: Fe448, z: Fe448) -> (Fe448, Fe448) {
    let (a, b) = x.apm(z);
    let a = a.sqr();
    let b = b.sqr();
    let x2 = a.mul(b);
    let difference = a.sub(b);
    let z2 = difference.mul_u32(C_A24).add(b).mul(difference);
    (x2, z2)
}

fn decode_scalar(scalar: &[u8; SCALAR_SIZE]) -> [u32; 14] {
    let mut words = [0_u32; 14];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes(
            scalar[index * 4..index * 4 + 4]
                .try_into()
                .expect("X448 scalar chunk has four bytes"),
        );
    }
    words[0] &= 0xFFFF_FFFC;
    words[13] |= 0x8000_0000;
    words
}

/// 常數時間：X448 純量乘法，回傳小端序的 u 座標。
///
/// 純量在解碼時自動依 RFC 7748 夾制；呼叫端不必先呼叫 [`clamp_private_key`]。
/// ladder 圈數固定，條件交換由 `cswap` 遮罩完成，秘密位元不決定分支或索引。
/// 最後的 `invert` 固定處理公開指數 `p - 2` 的 448 個位元；
/// 乘法步驟只由這個固定指數決定，不依秘密值分支。
///
/// 這是原語入口，不拒絕全零輸出；金鑰協議請用 [`calculate_agreement`]。
///
/// # Examples
///
/// [RFC 7748 §5.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2) 的第一組純量乘法向量。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let scalar = [
///     0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
///     0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
///     0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
///     0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
///     0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
///     0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
///     0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3,
/// ];
/// let u = [
///     0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf,
///     0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a,
///     0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f,
///     0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31,
///     0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
///     0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1,
///     0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86,
/// ];
/// let expected = [
///     0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66,
///     0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb,
///     0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54,
///     0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad,
///     0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77,
///     0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21,
///     0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f,
/// ];
/// assert_eq!(x448::scalar_mult(&scalar, &u), expected);
/// ```
pub fn scalar_mult(scalar: &[u8; SCALAR_SIZE], u: &[u8; POINT_SIZE]) -> [u8; POINT_SIZE] {
    let words = decode_scalar(scalar);
    let x1 = Fe448::decode(u);
    let mut x2 = x1;
    let mut z2 = Fe448::one();
    let mut x3 = Fe448::one();
    let mut z3 = Fe448::zero();
    debug_assert_eq!(words[13] >> 31, 1);

    let mut bit = 447_i32;
    let mut swap = Choice::from_lsb(1);
    loop {
        let (sum3, difference3) = x3.apm(z3);
        x3 = difference3;
        let (sum2, difference2) = x2.apm(z2);
        z3 = sum2;
        x2 = difference2;

        let product1 = sum3.mul(x2);
        x3 = x3.mul(z3);
        z3 = z3.sqr();
        x2 = x2.sqr();

        let difference = z3.sub(x2);
        z2 = difference.mul_u32(C_A24).add(x2).mul(difference);
        x2 = x2.mul(z3);

        let (sum, difference) = product1.apm(x3);
        x3 = sum.sqr();
        z3 = difference.sqr().mul(x1);

        bit -= 1;
        let word = (bit >> 5) as usize;
        let shift = bit & 31;
        let scalar_bit = Choice::from_lsb((words[word] >> shift) as u8);
        swap = swap ^ scalar_bit;
        (x2, x3) = Fe448::cswap(swap, x2, x3);
        (z2, z3) = Fe448::cswap(swap, z2, z3);
        swap = scalar_bit;

        if bit < 2 {
            break;
        }
    }
    debug_assert_eq!(swap.unwrap_u8(), 0); // The clamped low bits are public constants.

    // Clamp 清掉最低兩位，因此尾端固定做兩次倍點。
    for _ in 0..2 {
        (x2, z2) = point_double(x2, z2);
    }

    x2.mul(z2.invert()).encode()
}

/// 常數時間：X448 固定基點純量乘法。
///
/// 固定基點 `u = 5` 直接呼叫 [`scalar_mult`] 的固定圈數 ladder；
/// 條件交換使用 `cswap` 遮罩，最後的 `invert` 固定處理公開指數 `p - 2` 的 448 個位元；
/// 乘法步驟只由這個固定指數決定，不依秘密值分支。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
///
/// ```
/// use tc_rfc7748::x448;
///
/// let alice_private: [u8; x448::SCALAR_SIZE] = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let alice_public: [u8; x448::POINT_SIZE] = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::scalar_mult_base(&alice_private), alice_public);
/// ```
pub fn scalar_mult_base(scalar: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult(scalar, &BASE_POINT)
}

/// 常數時間：保留與 Bouncy Castle 對等的預算入口，不涉及秘密。
///
/// 這是空的 `const fn`，不初始化任何狀態。保留它是為了對齊 Bouncy Castle
/// 的 API 形狀；該實作會透過 Edwards 核心延遲建表並加鎖，
/// 目前這裡的 X448 固定基點直接走 ladder，沒有需要建立的表。
///
/// # Examples
///
/// [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2) 的 Alice 測試向量。
/// 預算入口可以呼叫，但公鑰運算不以呼叫過它為前提。
///
/// ```
/// use tc_rfc7748::x448;
///
/// x448::precompute();
/// let alice_private: [u8; x448::SCALAR_SIZE] = [
///     0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
///     0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
///     0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
///     0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
///     0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
///     0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
///     0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
/// ];
/// let alice_public: [u8; x448::POINT_SIZE] = [
///     0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
///     0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
///     0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
///     0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
///     0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
///     0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
///     0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
/// ];
/// assert_eq!(x448::generate_public_key(&alice_private), alice_public);
/// ```
pub const fn precompute() {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    struct SequenceRng(u8);

    impl TryRng for SequenceRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0_u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0_u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for SequenceRng {}

    fn hex(input: &str) -> [u8; 56] {
        let mut output = [0_u8; 56];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn clamp_and_private_key_generation_follow_rfc7748() {
        let mut private_key = [0xFF; SCALAR_SIZE];
        clamp_private_key(&mut private_key);
        assert_eq!(private_key[0], 0xFC);
        assert_eq!(private_key[SCALAR_SIZE - 1], 0xFF);

        let generated = generate_private_key(&mut SequenceRng(0));
        let mut expected = core::array::from_fn(|index| index as u8);
        clamp_private_key(&mut expected);
        assert_eq!(generated, expected);
    }

    #[test]
    fn rfc7748_scalar_mult_vectors() {
        let scalar1 = hex(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c\
             984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u1 = hex(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031\
             ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let expected1 = hex(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaa\
             deb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        );
        assert_eq!(scalar_mult(&scalar1, &u1), expected1);

        let scalar2 = hex(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd7\
             7c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u2 = hex(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015\
             894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        let expected2 = hex(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3\
             a5700df34321d62077e63633c575c1c954514e99da7c179d",
        );
        assert_eq!(scalar_mult(&scalar2, &u2), expected2);
    }

    #[test]
    fn rfc7748_ecdh_public_api_vector() {
        let alice_private = hex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5\
             74a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let alice_public = hex(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb\
             c836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let bob_private = hex(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120\
             bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let bob_public = hex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972\
             fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        let shared = hex(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56\
             fd2464c335543936521c24403085d59a449a5037514a879d",
        );

        assert_eq!(generate_public_key(&alice_private), alice_public);
        assert_eq!(generate_public_key(&bob_private), bob_public);
        assert_eq!(
            calculate_agreement(&alice_private, &bob_public),
            Some(shared)
        );
        assert_eq!(
            calculate_agreement(&bob_private, &alice_public),
            Some(shared)
        );
    }

    #[test]
    fn agreement_rejects_all_zero_result() {
        assert_eq!(
            calculate_agreement(&[0xA5; SCALAR_SIZE], &[0; POINT_SIZE]),
            None
        );
    }

    /// RFC 7748 §5.2 的 1000 次迭代向量。
    ///
    /// 1000 次 X448 純量乘法在 debug profile 約需 45 秒，佔這個 crate 測試
    /// 時間的八成以上（X25519 的同一項只要 2.7 秒——X448 的體域是 16 個
    /// radix-2²⁸ limb，純量也長得多）。因此預設不跑，改由
    /// `cargo test -p tc_rfc7748 -- --ignored` 執行；CI 有獨立步驟涵蓋。
    #[test]
    #[ignore = "1000 X448 ladder iterations; run with --ignored"]
    fn rfc7748_iterated_vector_at_1000() {
        let mut scalar = BASE_POINT;
        let mut u = scalar;
        for _ in 0..1_000 {
            let next = scalar_mult(&scalar, &u);
            u = scalar;
            scalar = next;
        }
        assert_eq!(
            scalar,
            hex(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67c\
                 f10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
            )
        );
    }
}
