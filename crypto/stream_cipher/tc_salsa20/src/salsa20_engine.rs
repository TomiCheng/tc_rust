use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::Salsa20PortableEngine;
#[cfg(feature = "rustcrypto")]
use crate::Salsa20RustCryptoEngine;
use crate::salsa;
use crate::salsa20_portable_engine::valid_rounds;

/// 目前金鑰用的後端。
enum Backend {
    #[cfg(feature = "rustcrypto")]
    RustCrypto(Salsa20RustCryptoEngine),
    Portable(Salsa20PortableEngine),
}

/// Salsa20（Bernstein, 2005），同 BC 的 `Salsa20Engine`：16 或 32 bytes 的金鑰、8 bytes 的 IV，回合數
/// 預設 20，[`with_rounds`](Self::with_rounds) 可選其他正偶數。
///
/// 開了 `rustcrypto` 時，32 bytes 金鑰、20 回合交給 RustCrypto 的 `Salsa20`；RustCrypto 沒有 16 bytes
/// 的金鑰，減回合版本也留在 [`Salsa20PortableEngine`]，所以開不開 feature 接受的金鑰與回合數都一樣。
/// 唯一差別是同一組金鑰與 IV 的上限：兩者都是 2^70 bytes，portable 回傳 `MaxBytesExceeded`、RustCrypto
/// 回傳 `CounterExhausted`，實際上都到不了。
///
/// **常數時間：** 兩個後端都只有 32 位元加法、XOR 與固定旋轉；後端依金鑰長度與回合數挑選，都是公開
/// 值。keystream 狀態在 drop 時清除；呼叫端的金鑰與暫存器、堆疊上的複本不在此列。
pub struct Salsa20Engine {
    rounds: usize,
    backend: Backend,
}

impl Salsa20Engine {
    /// 接受的金鑰長度（bytes）。
    pub const KEY_BYTES: [usize; 2] = Salsa20PortableEngine::KEY_BYTES;
    /// IV 長度（bytes）。
    pub const IV_BYTES: usize = Salsa20PortableEngine::IV_BYTES;
    /// 預設的回合數。
    pub const DEFAULT_ROUNDS: usize = salsa::DEFAULT_ROUNDS;

    /// 20 回合、還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self::build(salsa::DEFAULT_ROUNDS)
    }

    /// 指定正偶數回合數的引擎，不合時回傳 `InvalidRounds`。常數時間。
    pub const fn with_rounds(rounds: usize) -> Result<Self, InitError> {
        if !valid_rounds(rounds) {
            return Err(InitError::InvalidRounds(rounds));
        }
        Ok(Self::build(rounds))
    }

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            backend: Backend::Portable(Salsa20PortableEngine::build(rounds)),
        }
    }

    /// `key_bytes` bytes 金鑰用的新後端。
    #[cfg(feature = "rustcrypto")]
    fn backend_for(&self, key_bytes: usize) -> Backend {
        if self.rounds == salsa::DEFAULT_ROUNDS && key_bytes == Salsa20RustCryptoEngine::KEY_BYTES {
            Backend::RustCrypto(Salsa20RustCryptoEngine::new())
        } else {
            Backend::Portable(Salsa20PortableEngine::build(self.rounds))
        }
    }

    /// `key_bytes` bytes 金鑰用的新後端。
    #[cfg(not(feature = "rustcrypto"))]
    fn backend_for(&self, _key_bytes: usize) -> Backend {
        Backend::Portable(Salsa20PortableEngine::build(self.rounds))
    }
}

impl Default for Salsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Salsa20Engine {
    /// 寫出 `Salsa20`，回合數不是 20 時寫成 `Salsa20/12` 這樣，同 BC；不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rounds == salsa::DEFAULT_ROUNDS {
            f.write_str("Salsa20")
        } else {
            write!(f, "Salsa20/{}", self.rounds)
        }
    }
}

impl StreamCipher for Salsa20Engine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；錯誤見各後端。常數時間。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.return_byte(input),
            Backend::Portable(engine) => engine.return_byte(input),
        }
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；錯誤時不動 `output` 與位置。
    /// 常數時間；分支只看長度與位置。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.process_bytes(input, output),
            Backend::Portable(engine) => engine.process_bytes(input, output),
        }
    }

    /// 回到目前金鑰與 IV 的 keystream 開頭。常數時間。
    fn reset(&mut self) {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.reset(),
            Backend::Portable(engine) => engine.reset(),
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Salsa20Engine {
    type Error = InitError;

    /// 在涵蓋這組長度的後端裝入 16 或 32 bytes 的金鑰與 8 bytes 的 IV，從第 0 個區塊開始；方向不影響。
    /// 長度不對時保留原本的後端、金鑰、IV 與位置。常數時間；分支只看長度與回合數。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let mut backend = self.backend_for(params.key().len());
        match &mut backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.init(direction, params)?,
            Backend::Portable(engine) => engine.init(direction, params)?,
        }
        self.backend = backend;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipherInit};

    use super::{Backend, Salsa20Engine};

    /// 以 `key_bytes` bytes 的金鑰 init 後是否在 RustCrypto 上。
    fn on_rustcrypto(mut engine: Salsa20Engine, key_bytes: usize) -> bool {
        let params = KeyWithIvRef::new(&[0; 32][..key_bytes], &[0; 8]);
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        !matches!(engine.backend, Backend::Portable(_))
    }

    #[test]
    fn salsa20_engine_uses_rustcrypto_only_for_32_byte_keys_at_20_rounds_with_the_feature() {
        let rustcrypto = cfg!(feature = "rustcrypto");
        assert_eq!(on_rustcrypto(Salsa20Engine::new(), 32), rustcrypto);
        assert!(!on_rustcrypto(Salsa20Engine::new(), 16));
        assert!(!on_rustcrypto(Salsa20Engine::with_rounds(12).unwrap(), 32));
    }
}
