use core::fmt;

use rc4::{KeyInit, Rc4, StreamCipher as _};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const MAX_KEY_BYTES: usize = 256;

/// RC4 透過 RustCrypto 的 `rc4::Rc4`：1 到 256 bytes 的金鑰，沒有 IV。
///
/// `rc4::Rc4` 不能回到開頭，所以 `reset` 用保留的金鑰重跑金鑰排程；保留的金鑰與 RustCrypto 的置換表
/// 在 drop 時清除。
///
/// **變動時間（cache-timing）：** 和 [`Rc4PortableEngine`](crate::Rc4PortableEngine) 一樣，以置換表的
/// 值當索引交換與輸出，查表位置依秘密狀態而定；只為相容保留。
pub struct Rc4RustCryptoEngine {
    cipher: Option<Rc4>,
    key: [u8; MAX_KEY_BYTES],
    key_len: usize,
}

impl Rc4RustCryptoEngine {
    /// 最短的金鑰長度（bytes）。
    pub const MIN_KEY_BYTES: usize = 1;
    /// 最長的金鑰長度（bytes）。
    pub const MAX_KEY_BYTES: usize = MAX_KEY_BYTES;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            cipher: None,
            key: [0; MAX_KEY_BYTES],
            key_len: 0,
        }
    }
}

impl Default for Rc4RustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4RustCryptoEngine {
    /// 寫出 `RC4`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RC4")
    }
}

impl StreamCipher for Rc4RustCryptoEngine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`。變動時間（查表）。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
        let mut byte = [input];
        cipher.apply_keystream(&mut byte);
        Ok(byte[0])
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
    /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，兩者都不改變位置。變動時間
    /// （查表）。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
        let output = output
            .get_mut(..input.len())
            .ok_or(StreamError::BufferTooShort)?;
        cipher.apply_keystream_b2b(input, output);
        Ok(input.len())
    }

    /// 以保留的金鑰重跑金鑰排程，回到 keystream 開頭；`init` 之前什麼都不做。變動時間（重排置換表）。
    fn reset(&mut self) {
        if self.cipher.is_some() {
            // init 時已確認長度，這裡不會失敗
            self.cipher = Rc4::new_from_slice(&self.key[..self.key_len]).ok();
        }
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4RustCryptoEngine {
    type Error = InitError;

    /// 裝入 1 到 256 bytes 的金鑰；方向不影響。長度不對時保留原本的金鑰與位置。變動時間（排列置換表時
    /// 以金鑰與狀態當索引）。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let cipher =
            Rc4::new_from_slice(key).map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.key.zeroize();
        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.cipher = Some(cipher);
        Ok(())
    }
}

impl Drop for Rc4RustCryptoEngine {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_wrapped_rustcrypto_cipher_wipes_its_state_on_drop() {
        fn wiped_on_drop<T: rc4::cipher::zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<rc4::Rc4>();
    }
}
