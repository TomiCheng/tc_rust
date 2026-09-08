//! 預設盲化私鑰運算的 RSA 對外引擎。

use rand_core::CryptoRng;
use tc_cipher::{AsymmetricBlockCipher, CipherDirection};

use crate::{RsaCrt, RsaCrtInit, RsaError, RsaPrivateCrtKeyParams};

/// 包住 CRT 核心並持有亂數來源的門面，私鑰運算一律盲化。
///
/// 型別參數 `E` 受限於 [`RsaCrt`]，所以只有 CRT 核心包得進來——非 CRT 核心沒有
/// [`RsaCrt::process_int_blinded`]，編譯期就被擋掉。這與 Bouncy Castle 不同：
/// 它的 `RsaBlindedEngine` 收到非 CRT 私鑰時會靜靜地跳過盲化。
///
/// [`AsymmetricBlockCipher::process_block`] 走的是盲化路徑；需要不盲化的原始
/// 運算時直接使用核心引擎，不要經過這一層。
///
/// # 範例
///
/// 小型測試金鑰與決定性 RNG 僅供範例，不可用於實際場合。
/// [`Self::core`] 可借出核心查詢大小、轉換公開輸入，但只提供不可變參照，
/// 不能透過它呼叫需要 `&mut self` 的模冪方法。公鑰模冪使用另一個公鑰核心。
///
/// ```
/// use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
/// use tc_rsa::{
///     Rsa, Rsa2048Core, Rsa2048CrtCore, RsaBlindedEngine, RsaCrtInit,
///     RsaInit, RsaKeyRef, RsaPrivateCrtKeyRef,
/// };
///
/// # fn main() -> Result<(), tc_rsa::RsaError> {
/// let key = RsaPrivateCrtKeyRef::new(
///     &[0x0f, 0xf7], &[7], &[0x08, 0xd7], &[67], &[61], &[19], &[43], &[11],
/// );
/// let mut engine: RsaBlindedEngine<Rsa2048CrtCore, _> =
///     RsaBlindedEngine::new(ExampleRng(1));
/// engine.init(CipherDirection::Decrypt, &key)?;
///
/// // 借用核心做公開輸入的轉換；這一步不執行私鑰模冪，也不取用 RNG。
/// let core = engine.core();
/// assert_eq!(core.input_block_size(), 2);
/// let input = core.convert_input(&[2])?;
/// let mut encoded = [0_u8; 2];
/// let len = core.convert_output(&input, &mut encoded)?;
/// assert_eq!(&encoded[..len], &[2]);
///
/// let mut result = [0_u8; 2];
/// let len = engine.process_block(&[2], &mut result)?;
/// assert_eq!(&result[..len], &[1, 92]);
///
/// // 公鑰核心不含盲化；以公開指數驗證剛才的私鑰運算。
/// let public_key = RsaKeyRef::new(false, key.modulus(), key.public_exponent());
/// let mut public = Rsa2048Core::default();
/// public.init(CipherDirection::Encrypt, &public_key)?;
/// let mut recovered = [0_u8; 2];
/// let recovered_len = public.process_block(&result[..len], &mut recovered)?;
/// assert_eq!(&recovered[..recovered_len], &[0, 2]);
/// # Ok::<(), tc_rsa::RsaError>(())
/// # }
/// #
/// # // 決定性 RNG 僅供範例，不可用於實際場合。
/// # struct ExampleRng(u64);
/// # impl rand_core::TryRng for ExampleRng {
/// #     type Error = core::convert::Infallible;
/// #     fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
/// #         Ok(self.try_next_u64()? as u32)
/// #     }
/// #     fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
/// #         self.0 ^= self.0 << 13;
/// #         self.0 ^= self.0 >> 7;
/// #         self.0 ^= self.0 << 17;
/// #         Ok(self.0)
/// #     }
/// #     fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
/// #         for chunk in output.chunks_mut(8) {
/// #             let bytes = self.try_next_u64()?.to_le_bytes();
/// #             chunk.copy_from_slice(&bytes[..chunk.len()]);
/// #         }
/// #         Ok(())
/// #     }
/// # }
/// # impl rand_core::TryCryptoRng for ExampleRng {}
/// ```
#[derive(Clone, Debug)]
pub struct RsaBlindedEngine<E, R> {
    core: E,
    rng: R,
}

impl<E: Default, R> RsaBlindedEngine<E, R> {
    /// 以外部亂數來源建立尚未持有金鑰的引擎。
    pub fn new(rng: R) -> Self {
        Self {
            core: E::default(),
            rng,
        }
    }
}

impl<E, R> RsaBlindedEngine<E, R> {
    /// 以既有的核心與亂數來源建立引擎。
    pub const fn from_parts(core: E, rng: R) -> Self {
        Self { core, rng }
    }

    /// 借出內部核心，供查詢區塊大小及轉換公開輸入使用。
    ///
    /// 回傳不可變參照，不會執行盲化，也不能藉此呼叫需要可變參照的模冪方法。
    pub const fn core(&self) -> &E {
        &self.core
    }

    /// 拆回核心與亂數來源。
    pub fn into_parts(self) -> (E, R) {
        (self.core, self.rng)
    }
}

impl<E, R, K> RsaCrtInit<K> for RsaBlindedEngine<E, R>
where
    E: RsaCrtInit<K, Error = RsaError>,
    K: RsaPrivateCrtKeyParams + ?Sized,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        self.core.init(direction, parameters)
    }
}

impl<E, R> AsymmetricBlockCipher for RsaBlindedEngine<E, R>
where
    E: RsaCrt<Error = RsaError>,
    R: CryptoRng,
{
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.core.input_block_size()
    }

    fn output_block_size(&self) -> usize {
        self.core.output_block_size()
    }

    /// 位元組層的單一區塊運算，中間的私鑰運算每次重新取樣盲化因子。
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.core.convert_input(input)?;
        let result = self.core.process_int_blinded(&value, &mut self.rng)?;
        self.core.convert_output(&result, output)
    }
}
