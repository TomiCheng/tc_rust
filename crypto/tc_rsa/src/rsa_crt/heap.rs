//! 以堆配置的 CRT 私鑰核心；模數寬度在執行期決定。

use rand_core::CryptoRng;
use tc_bigint::{BigUint, NonZero, RandomMod};
use tc_cipher::CipherDirection;

use crate::rsa_crt::validate;
use crate::{Rsa, RsaCrt, RsaCrtInit, RsaError, RsaPrivateCrtKeyParams};

/// 以中國剩餘定理加速、寬度不設限的私鑰核心。
///
/// 相對於 [`FixedRsaCrtCoreEngine`](crate::FixedRsaCrtCoreEngine)，這個版本不需要在
/// 編譯期知道模數或質因數大小，適合寬度只有執行期才確定的場合，例如解析任意來源的
/// 憑證或 PKCS#8 金鑰。
///
/// # 不保證常數時間
///
/// 底層的 [`BigUint`] 是長度隨數值變動的堆配置整數，`mod_pow` 與 `mod_inverse`
/// 都沒有固定排程，而且秘密材料會留在無法歸零的堆緩衝區裡。CRT 的中間值
/// `m_p`、`m_q`、`h` 都是秘密，其長度隨值變動；Lenstra 比較也不是常數時間。
/// [`RsaCrt::process_block_blinded`] 仍會在每次運算重新取樣盲化因子，降低遠端計時
/// 的可觀測性，但不等同固定排程。需要固定排程的私鑰運算請改用固定寬度版本。
///
/// 以 [`Default`] 建立的引擎尚未持有金鑰，運算方法會回
/// [`RsaError::NotInitialized`]，區塊大小則為 `0`。
#[derive(Clone, Debug, Default)]
pub struct HeapRsaCrtCoreEngine {
    inner: Option<Inner>,
}

/// 初始化後才存在的狀態。
#[derive(Clone, Debug)]
struct Inner {
    modulus: BigUint,
    public_exponent: BigUint,
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    q_inv: BigUint,
    bit_size: usize,
    direction: CipherDirection,
}

impl Inner {
    fn new<K: RsaPrivateCrtKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let bit_size = validate(key)?;

        Ok(Self {
            modulus: BigUint::from_be_bytes(key.modulus()),
            public_exponent: BigUint::from_be_bytes(key.public_exponent()),
            p: BigUint::from_be_bytes(key.p()),
            q: BigUint::from_be_bytes(key.q()),
            dp: BigUint::from_be_bytes(key.dp()),
            dq: BigUint::from_be_bytes(key.dq()),
            q_inv: BigUint::from_be_bytes(key.q_inv()),
            bit_size,
            direction,
        })
    }
}

impl HeapRsaCrtCoreEngine {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaPrivateCrtKeyParams + ?Sized> RsaCrtInit<K> for HeapRsaCrtCoreEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl Rsa for HeapRsaCrtCoreEngine {
    type RsaBigInt = BigUint;
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.saturating_sub(1) / 8,
                CipherDirection::Decrypt => inner.bit_size.div_ceil(8),
            })
    }

    fn output_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
                CipherDirection::Decrypt => inner.bit_size.saturating_sub(1) / 8,
            })
    }

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let input = BigUint::from_be_bytes(input);
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= BigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= &inner.modulus - BigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    /// 不盲化的 CRT 運算。
    ///
    /// 只做中國剩餘定理與 Lenstra 故障檢查，**不含盲化**。私鑰暴露在遠端計時
    /// 之下時請改用 [`RsaCrt::process_block_blinded`]。
    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        self.inner()?.process_crt(input)
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let inner = self.inner()?;
        let bytes = result.to_be_bytes();
        let result_len = bytes.len();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
            CipherDirection::Decrypt => result_len,
        };
        if output.len() < output_len || result_len > output_len {
            return Err(RsaError::OutputTooShort);
        }

        output[..output_len].fill(0);
        output[output_len - result_len..output_len].copy_from_slice(&bytes);
        Ok(output_len)
    }
}

impl RsaCrt for HeapRsaCrtCoreEngine {
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &Self::RsaBigInt,
        rng: &mut R,
    ) -> Result<Self::RsaBigInt, Self::Error> {
        self.inner()?.process_blinded(input, rng)
    }
}

impl Inner {
    /// 以中國剩餘定理計算 `input^d mod n`，並用公開指數驗算結果。
    fn process_crt(&self, input: &BigUint) -> Result<BigUint, RsaError> {
        let m_p = input.mod_pow(&self.dp, &self.p);
        let m_q = input.mod_pow(&self.dq, &self.q);
        // m_q 可能大於 p；先約簡到 p 的範圍再補上 p，避免無號減法下溢。
        let h = ((m_p + &self.p - (&m_q % &self.p)) * &self.q_inv) % &self.p;
        let result = m_q + h * &self.q;
        let check = result.mod_pow(&self.public_exponent, &self.modulus);

        // 單邊算錯就能從 gcd(result^e - input, n) 分解 n，所以結果必須先驗算過才交出去。
        // 判定只決定是否回傳，不會揭露未通過驗證的私密中間值。
        if check != *input {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }
        Ok(result)
    }

    /// 以每次重新取樣的盲化因子包住 CRT 運算。
    ///
    /// 取 `r` 均勻分布於 `[1, n-1]`，先乘上 `r^e`、算完再乘 `r^-1`，讓可觀測的
    /// 中間值與真正的輸入無關。
    fn process_blinded<R: CryptoRng + ?Sized>(
        &self,
        input: &BigUint,
        rng: &mut R,
    ) -> Result<BigUint, RsaError> {
        let upper =
            NonZero::new(&self.modulus - BigUint::from(1_u8)).ok_or(RsaError::InvalidModulus)?;
        let r = BigUint::random_mod_vartime(rng, &upper) + BigUint::from(1_u8);

        let blind = r.mod_pow(&self.public_exponent, &self.modulus);
        // 堆版沿用 BigUint 的變動時間模反元素，沒有固定步數的保證。
        let inverse = r
            .mod_inverse(&self.modulus)
            .ok_or(RsaError::FaultyDecryptionOrSigning)?;
        let blinded_input = (input * blind) % &self.modulus;
        let blinded_result = self.process_crt(&blinded_input)?;

        Ok((blinded_result * inverse) % &self.modulus)
    }
}
