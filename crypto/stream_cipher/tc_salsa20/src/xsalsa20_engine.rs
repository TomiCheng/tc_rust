use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

#[cfg(not(feature = "rustcrypto"))]
use crate::Xsalsa20PortableEngine as Inner;
#[cfg(feature = "rustcrypto")]
use crate::Xsalsa20RustCryptoEngine as Inner;

/// XSalsa20（Bernstein, 2008），同 BC 的 `XSalsa20Engine`：32 bytes 的金鑰與 24 bytes 的 IV。開了
/// `rustcrypto` 時跑在 RustCrypto 的 `XSalsa20` 上，沒開時跑在
/// [`Xsalsa20PortableEngine`](crate::Xsalsa20PortableEngine)；兩者接受同樣的金鑰與 IV，後端在編譯時
/// 決定。
///
/// **常數時間：** 兩個後端都只有 32 位元加法、XOR 與固定旋轉。keystream 狀態在 drop 時清除；呼叫端的
/// 金鑰與暫存器、堆疊上的複本不在此列。
pub struct Xsalsa20Engine {
    inner: Inner,
}

impl Xsalsa20Engine {
    /// 金鑰長度（bytes）。
    pub const KEY_BYTES: usize = 32;
    /// IV 長度（bytes）。
    pub const IV_BYTES: usize = 24;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

impl Default for Xsalsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Xsalsa20Engine {
    /// 寫出 `XSalsa20`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl StreamCipher for Xsalsa20Engine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；錯誤見後端。常數時間。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.inner.return_byte(input)
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；錯誤時不動 `output` 與位置。
    /// 常數時間；分支只看長度與位置。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.inner.process_bytes(input, output)
    }

    /// 回到目前金鑰與 IV 的 keystream 開頭。常數時間。
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Xsalsa20Engine {
    type Error = InitError;

    /// 裝入 32 bytes 的金鑰與 24 bytes 的 IV，從第 0 個區塊開始；方向不影響。長度不對時保留原本的
    /// 金鑰、IV 與位置。常數時間；分支只看長度。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
