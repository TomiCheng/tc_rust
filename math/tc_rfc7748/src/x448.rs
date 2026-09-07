//! X448 — RFC 7748 Diffie-Hellman over Curve448.
//!
//! 這個模組使用 16-limb radix-2²⁸ 欄位與 Montgomery ladder。固定基點目前
//! 也走同一條 ladder；等 Ed448 固定基點核心加入後，只需替換
//! [`scalar_mult_base`] 的內部實作，公開 API 不會改變。

use super::x448_field::Fe448;
use rand_core::CryptoRng;
use tc_constant_time::Choice;

/// X448 `u` 座標與輸出的 byte 長度。
pub const POINT_SIZE: usize = 56;
/// X448 scalar 與私鑰的 byte 長度。
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

/// 依 RFC 7748 section 5 夾制 X448 私鑰。
///
/// X448 清除最低兩位並設定最高位。即使呼叫端未先夾制，[`scalar_mult`]
/// 也會在 scalar 解碼時套用同一規則。
pub fn clamp_private_key(private_key: &mut [u8; SCALAR_SIZE]) {
    private_key[0] &= 0xFC;
    private_key[SCALAR_SIZE - 1] |= 0x80;
}

/// 使用呼叫端提供的密碼學安全亂數來源產生已夾制的 X448 私鑰。
pub fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; SCALAR_SIZE] {
    let mut private_key = [0_u8; SCALAR_SIZE];
    rng.fill_bytes(&mut private_key);
    clamp_private_key(&mut private_key);
    private_key
}

/// 從 X448 私鑰產生公開鍵。
pub fn generate_public_key(private_key: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult_base(private_key)
}

/// 計算 X448 Diffie-Hellman shared secret。
///
/// 回傳 `None` 代表結果全零，也就是對方送入低階點。檢查會掃過完整輸出，
/// 不會在第一個非零 byte 提前結束。
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

/// X448 scalar multiplication。
///
/// `scalar` 會在內部依 RFC 7748 自動夾制；ladder 的分支與記憶體存取不依賴
/// 秘密位元，條件交換由遮罩完成。
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

/// X448 固定基點乘法。
///
/// 目前使用 `u = 5` 的通用 Montgomery ladder。x-only ladder 無法把任意點預算
/// 成加法表；未來的快速路徑需要 Ed448 完整點加法核心。
pub fn scalar_mult_base(scalar: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult(scalar, &BASE_POINT)
}

/// 為未來 Ed448 固定基點表保留的 API。
///
/// 現有 ladder 不含執行期表，因此這個函式目前無需初始化任何狀態。
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

    #[test]
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
