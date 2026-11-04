use core::fmt;

use tc_macs::{InitError, Mac, MacError, MacInit};
use tc_skein::{SkeinEngine, SkeinParams};

const MIN_KEY_BYTES: usize = 16;

/// Skein-MAC。金鑰與其他參數由 [`SkeinParams`] 提供；drop 時由引擎清除狀態。
#[derive(Clone)]
pub struct SkeinMac {
    engine: SkeinEngine,
    initialised: bool,
}

impl SkeinMac {
    /// 256 位元的狀態大小。
    pub const SKEIN_256: usize = SkeinEngine::SKEIN_256;
    /// 512 位元的狀態大小。
    pub const SKEIN_512: usize = SkeinEngine::SKEIN_512;
    /// 1024 位元的狀態大小。
    pub const SKEIN_1024: usize = SkeinEngine::SKEIN_1024;

    /// 建立未初始化的 MAC。常數時間。狀態或輸出大小不合法時 panic，同 BC 丟例外。
    pub fn new(state_size_bits: usize, output_size_bits: usize) -> Self {
        Self {
            engine: SkeinEngine::new(state_size_bits, output_size_bits),
            initialised: false,
        }
    }
}

impl fmt::Display for SkeinMac {
    /// 寫出 BC 的名稱，例如 `Skein-MAC-512-256`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Skein-MAC-{}-{}",
            self.engine.block_size() * 8,
            self.engine.output_size() * 8
        )
    }
}

impl Mac for SkeinMac {
    type Error = MacError;

    /// 回傳 tag 的位元組數。常數時間。
    fn mac_size(&self) -> usize {
        self.engine.output_size()
    }

    /// 加入訊息。常數時間。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialised {
            return Err(MacError::NotInitialised);
        }
        self.engine.update(input);
        Ok(())
    }

    /// 寫出 tag，並以同一把金鑰開始下一則訊息。常數時間。
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(MacError::NotInitialised);
        }
        let required = self.engine.output_size();
        if output.len() < required {
            return Err(MacError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        Ok(self.engine.do_final(output))
    }

    /// 捨棄訊息並保留金鑰。常數時間。
    fn reset(&mut self) {
        self.engine.reset();
    }
}

impl<P: SkeinParams + ?Sized> MacInit<P> for SkeinMac {
    type Error = InitError;

    /// 以 `params` 設定金鑰並開始新訊息；沒有金鑰或短於 16 bytes 都拒絕，同 BC。常數時間。
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialised = false;
        let key_len = params.key().map_or(0, <[u8]>::len);
        if key_len < MIN_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key_len));
        }
        self.engine
            .init(params)
            .map_err(|_| InitError::InternalFailure)?;
        self.initialised = true;
        Ok(())
    }
}
