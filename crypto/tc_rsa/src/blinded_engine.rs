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

    /// 借出內部核心，供不盲化的公開運算使用。
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
