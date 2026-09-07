use rand_core::CryptoRng;
use tc_digest::Digest;
use tc_ec_core::{Point, SecretCurve, SecretField, multiply_secret, sum_of_two_multiplies};

use crate::scalar::bits_to_int;
use crate::{
    EcdsaError, EcdsaScalar, HMacKCalculator, KCalculator, RandomKCalculator, SigningKey,
    VerifyingKey,
};

/// 取訊息雜湊最左邊 `n.bit_length()` 個 bit；輸入較短時保留原值。
pub fn calculate_e<S: EcdsaScalar>(n: &S, message_hash: &[u8]) -> Result<S, EcdsaError> {
    bits_to_int(n, message_hash).ok_or(EcdsaError::ScalarOutOfRange)
}

/// 使用 RFC 6979 HMAC 計算 `k` 並產生 ECDSA 簽章。
pub fn sign_deterministic<C, D>(
    key: &SigningKey<C>,
    message_hash: &[u8],
    digest: D,
) -> Result<(C::Scalar, C::Scalar), EcdsaError>
where
    C: SecretCurve,
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
    D: Digest,
{
    let n = key.curve().order().expect("SigningKey 已驗證曲線階");
    let mut calculator = HMacKCalculator::new(digest);
    calculator.init(n, key.private_scalar(), message_hash);
    sign_with_calculator(key, message_hash, &mut calculator)
}

/// 使用呼叫端提供的密碼學亂數產生 ECDSA 簽章。
pub fn sign_randomized<C, R>(
    key: &SigningKey<C>,
    message_hash: &[u8],
    rng: &mut R,
) -> Result<(C::Scalar, C::Scalar), EcdsaError>
where
    C: SecretCurve,
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
    R: CryptoRng + ?Sized,
{
    let n = key.curve().order().expect("SigningKey 已驗證曲線階");
    let mut calculator = RandomKCalculator::new(n, rng);
    sign_with_calculator(key, message_hash, &mut calculator)
}

/// 使用已初始化的 `k` 計算器產生 ECDSA 簽章。
///
/// `r == 0` 或 `s == 0` 時會重試；這會揭露極低機率的重試事件，與 Bouncy
/// Castle 的行為一致。到 `kG` 完成前不會解密秘密點表示。
pub fn sign_with_calculator<C, K>(
    key: &SigningKey<C>,
    message_hash: &[u8],
    calculator: &mut K,
) -> Result<(C::Scalar, C::Scalar), EcdsaError>
where
    C: SecretCurve,
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
    K: KCalculator<C::Scalar>,
{
    let n = key.curve().order().expect("SigningKey 已驗證曲線階");
    let odd_n = tc_bigint::Odd::new(*n).expect("SigningKey 已驗證奇數曲線階");
    let e = calculate_e(n, message_hash)?;

    loop {
        let (k, r) = loop {
            let k = calculator.next_k();
            let point = multiply_secret::<C>(key.generator(), &k.to_le_bytes_fixed())
                .map_err(|_| EcdsaError::CurveOperation)?;
            // `r` 是公開簽章分量；只有完整固定排程純量乘法後才 reveal。
            let point = point.reveal().normalize();
            let x = point.x().ok_or(EcdsaError::CurveOperation)?;
            let r = C::field_element_to_scalar(&x)
                .ok_or(EcdsaError::CoordinateOutOfRange)?
                .rem_public(n);
            if !r.is_zero() {
                break (k, r);
            }
        };

        let inverse = k.inverse_ct(&odd_n).ok_or(EcdsaError::NotInvertible)?;
        let s = inverse.mul_add_ct(&e, key.private_scalar(), &r, &odd_n);
        if !s.is_zero() {
            return Ok((r, s));
        }
    }
}

/// 驗證 ECDSA 簽章。
///
/// 驗證輸入全是公開資料，因此反元素、模乘與雙純量乘法刻意使用變動時間路徑。
pub fn verify<C>(key: &VerifyingKey<C>, message_hash: &[u8], r: &C::Scalar, s: &C::Scalar) -> bool
where
    C: SecretCurve,
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
{
    let n = key.curve().order().expect("VerifyingKey 已驗證曲線階");
    if r.is_zero() || s.is_zero() || *r >= *n || *s >= *n {
        return false;
    }
    let Ok(e) = calculate_e(n, message_hash) else {
        return false;
    };
    let Some(c) = s.inverse_vartime(n) else {
        return false;
    };
    let u1 = e.mul_mod_public(&c, n);
    let u2 = r.mul_mod_public(&c, n);
    let Ok(point) = sum_of_two_multiplies::<C>(key.generator(), &u1, key.public_point(), &u2)
    else {
        return false;
    };
    if point.is_identity() {
        return false;
    }
    let point = point.normalize();
    let Some(x) = point.x() else {
        return false;
    };
    C::field_element_to_scalar(&x).is_some_and(|x| x.rem_public(n) == *r)
}
