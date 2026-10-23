use core::fmt;

use salsa20::cipher::{KeyIvInit, StreamCipher as _, StreamCipherSeek as _};
use salsa20::{Salsa20, XSalsa20};
use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

// 兩個引擎只差 RustCrypto 的型別、IV 長度與名稱
macro_rules! rustcrypto_engine {
    (
        $(#[$meta:meta])*
        $name:ident($cipher:ty), iv_bytes: $iv_bytes:literal, algo_name: $algo_name:literal
    ) => {
        $(#[$meta])*
        pub struct $name {
            cipher: Option<$cipher>,
        }

        impl $name {
            /// 金鑰長度（bytes）。
            pub const KEY_BYTES: usize = 32;
            /// IV 長度（bytes）。
            pub const IV_BYTES: usize = $iv_bytes;

            /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
            pub const fn new() -> Self {
                Self { cipher: None }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            /// 寫出演算法名稱，不碰金鑰。常數時間。
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($algo_name)
            }
        }

        impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for $name {
            type Error = InitError;

            /// 裝入 32 bytes 的金鑰與 [`IV_BYTES`](Self::IV_BYTES) bytes 的 IV，從第 0 個區塊開始；方向
            /// 不影響。長度不對時保留原本的金鑰、IV 與位置。常數時間；分支只看長度。
            fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
                let key = params.key();
                let iv = params.iv();
                if key.len() != Self::KEY_BYTES {
                    return Err(InitError::InvalidKeyLength(key.len()));
                }
                if iv.len() != Self::IV_BYTES {
                    return Err(InitError::InvalidIvLength(iv.len()));
                }
                // 長度上面已檢查，這裡不會失敗
                let cipher = <$cipher>::new_from_slices(key, iv)
                    .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
                self.cipher = Some(cipher);
                Ok(())
            }
        }

        impl StreamCipher for $name {
            type Error = StreamError;

            /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`，keystream 用完時回傳
            /// `CounterExhausted`。常數時間。
            fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let mut byte = [input];
                cipher
                    .try_apply_keystream(&mut byte)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(byte[0])
            }

            /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
            /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，會超過 keystream 時
            /// 回傳 `CounterExhausted`，錯誤時不動 `output` 與位置。常數時間；分支只看長度。
            fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let output = output
                    .get_mut(..input.len())
                    .ok_or(StreamError::BufferTooShort)?;
                cipher
                    .try_apply_keystream_b2b(input, output)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(input.len())
            }

            /// 回到目前金鑰與 IV 的 keystream 開頭；`init` 之前什麼都不做。常數時間。
            fn reset(&mut self) {
                if let Some(cipher) = &mut self.cipher {
                    cipher.seek(0u64);
                }
            }
        }
    };
}

rustcrypto_engine! {
    /// Salsa20 透過 RustCrypto 的 `salsa20::Salsa20`：32 bytes 的金鑰、8 bytes 的 IV、20 回合。
    ///
    /// **常數時間：** Salsa20 只有 32 位元加法、XOR 與固定旋轉；RustCrypto 依處理器功能挑選後端，
    /// 那是公開資訊。狀態與緩衝的 keystream 在 drop 時清除；呼叫端的金鑰與暫存器、堆疊上的複本
    /// 不在此列。
    Salsa20RustCryptoEngine(Salsa20), iv_bytes: 8, algo_name: "Salsa20"
}

rustcrypto_engine! {
    /// XSalsa20 透過 RustCrypto 的 `salsa20::XSalsa20`：32 bytes 的金鑰、24 bytes 的 IV。
    ///
    /// **常數時間：** 同 [`Salsa20RustCryptoEngine`]，HSalsa20 也只有 ARX 運算。狀態與緩衝的 keystream
    /// 在 drop 時清除。
    Xsalsa20RustCryptoEngine(XSalsa20), iv_bytes: 24, algo_name: "XSalsa20"
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_wrapped_rustcrypto_ciphers_wipe_their_state_and_buffered_keystream_on_drop() {
        fn wiped_on_drop<T: cipher::zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<salsa20::Salsa20>();
        wiped_on_drop::<salsa20::XSalsa20>();
    }
}
