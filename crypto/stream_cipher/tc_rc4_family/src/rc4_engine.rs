use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

#[cfg(not(feature = "rustcrypto"))]
use crate::Rc4PortableEngine as Inner;
#[cfg(feature = "rustcrypto")]
use crate::Rc4RustCryptoEngine as Inner;

/// RC4（Rivest, 1987），同 BC 的 `RC4Engine`：1 到 256 bytes 的金鑰，沒有 IV。開了 `rustcrypto` 時跑在
/// RustCrypto 的 `rc4` 上，沒開時跑在 [`Rc4PortableEngine`](crate::Rc4PortableEngine)；兩者接受同樣的
/// 金鑰，後端在編譯時決定。
///
/// **變動時間（cache-timing）：** 兩個後端都以置換表的值當索引交換與輸出，查表位置依秘密狀態而定。
/// RC4 的 keystream 有已知偏差，已被攻破；只為相容保留。置換表與金鑰在 drop 時清除。
pub struct Rc4Engine {
    inner: Inner,
}

impl Rc4Engine {
    /// 最短的金鑰長度（bytes）。
    pub const MIN_KEY_BYTES: usize = 1;
    /// 最長的金鑰長度（bytes）。
    pub const MAX_KEY_BYTES: usize = 256;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

impl Default for Rc4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4Engine {
    /// 寫出 `RC4`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl StreamCipher for Rc4Engine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`。變動時間（查表）。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.inner.return_byte(input)
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；錯誤時不動 `output` 與位置。
    /// 變動時間（查表）。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.inner.process_bytes(input, output)
    }

    /// 回到目前金鑰的 keystream 開頭。變動時間（重排置換表）。
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4Engine {
    type Error = InitError;

    /// 裝入 1 到 256 bytes 的金鑰；方向不影響。長度不對時保留原本的金鑰與位置。變動時間（排列置換表時
    /// 以金鑰與狀態當索引）。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
