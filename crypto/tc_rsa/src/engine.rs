//! 預設啟用私鑰盲化的 RSA 對外引擎。

use rand_core::CryptoRng;
use tc_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};

use crate::core::RsaCoreEngine;
use crate::{RsaError, RsaKey, RsaKeyParameters, RsaPrivateCrtKeyParameters};

/// 原始 RSA 引擎；CRT 私鑰運算會自動盲化。
pub struct RsaBlindedEngine<R> {
    core: RsaCoreEngine,
    rng: R,
}

impl<R> RsaBlindedEngine<R> {
    /// 以外部亂數來源及已驗證的金鑰建立引擎。
    pub fn new<'a, P>(rng: R, direction: CipherDirection, params: P) -> Result<Self, RsaError>
    where
        P: Into<RsaKey<'a>>,
    {
        let params = params.into();
        Ok(Self {
            core: RsaCoreEngine::new(direction, &params)?,
            rng,
        })
    }

    /// 重新設定運算方向與金鑰。
    pub fn init<'a, P>(&mut self, direction: CipherDirection, params: P) -> Result<(), RsaError>
    where
        P: Into<RsaKey<'a>>,
    {
        let params = params.into();
        self.core = RsaCoreEngine::new(direction, &params)?;
        Ok(())
    }

    /// 取回引擎持有的亂數來源。
    pub fn into_rng(self) -> R {
        self.rng
    }
}

impl<R: CryptoRng> AsymmetricBlockCipher for RsaBlindedEngine<R> {
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.core.input_block_size()
    }

    fn output_block_size(&self) -> usize {
        self.core.output_block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_block(input, output, &mut self.rng)
    }
}

impl<'a, R> AsymmetricBlockCipherInit<RsaKey<'a>> for RsaBlindedEngine<R> {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &RsaKey<'a>) -> Result<(), Self::Error> {
        self.core = RsaCoreEngine::new(direction, params)?;
        Ok(())
    }
}

impl<'a, R> AsymmetricBlockCipherInit<RsaKeyParameters<'a>> for RsaBlindedEngine<R> {
    type Error = RsaError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &RsaKeyParameters<'a>,
    ) -> Result<(), Self::Error> {
        self.core = RsaCoreEngine::new(direction, &(*params).into())?;
        Ok(())
    }
}

impl<'a, R> AsymmetricBlockCipherInit<RsaPrivateCrtKeyParameters<'a>> for RsaBlindedEngine<R> {
    type Error = RsaError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &RsaPrivateCrtKeyParameters<'a>,
    ) -> Result<(), Self::Error> {
        self.core = RsaCoreEngine::new(direction, &(*params).into())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
