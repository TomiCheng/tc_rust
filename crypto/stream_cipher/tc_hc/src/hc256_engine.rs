use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const TABLE_WORDS: usize = 1024;
const COUNTER_MASK: usize = 2047;
const FULL_KEY_BYTES: usize = 32;
const FULL_IV_BYTES: usize = 32;

/// HC-256（Wu, 2004），同 BC 的 `HC256Engine`：金鑰 16 或 32 bytes，IV 至少 16 bytes。BC 把 16
/// bytes 的金鑰重複一次補成 32 bytes，不足 32 bytes 的 IV 以開頭補滿，超過的只用前 32 bytes；這裡
/// 照做。
///
/// **變動時間（cache-timing）：** 每一步以內部狀態查 p、q 表（包括兩表交叉的一項），查表位置依秘密
/// 狀態而定，共用快取的環境下可能洩漏；HC 沒有常數時間的版本，只為相容保留。其餘只有 32 位元
/// 加法、XOR 與固定旋轉，分支只看長度與位置。金鑰、IV 與兩張表在 drop 時清除。
pub struct Hc256Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; FULL_KEY_BYTES],
    iv: [u8; FULL_IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc256Engine {
    /// 接受的金鑰長度（bytes）。
    pub const KEY_BYTES: [usize; 2] = [16, 32];
    /// IV 的最短長度（bytes）。
    pub const MIN_IV_BYTES: usize = 16;
    /// 實際用到的 IV 長度（bytes）。
    pub const IV_BYTES: usize = FULL_IV_BYTES;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            p: [0; TABLE_WORDS],
            q: [0; TABLE_WORDS],
            counter: 0,
            key: [0; FULL_KEY_BYTES],
            iv: [0; FULL_IV_BYTES],
            word: [0; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let index = self.counter & 1023;
        let index3 = index.wrapping_sub(3) & 1023;
        let index10 = index.wrapping_sub(10) & 1023;
        let index12 = index.wrapping_sub(12) & 1023;
        let index1023 = index.wrapping_sub(1023) & 1023;
        let result = if self.counter < 1024 {
            let x = self.p[index3];
            let y = self.p[index1023];
            let cross = self.q[((x ^ y) & 1023) as usize];
            self.p[index] = self.p[index]
                .wrapping_add(self.p[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.p[index12];
            let h = self.q[(x & 0xff) as usize]
                .wrapping_add(self.q[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.q[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.q[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.p[index]
        } else {
            let x = self.q[index3];
            let y = self.q[index1023];
            let cross = self.p[((x ^ y) & 1023) as usize];
            self.q[index] = self.q[index]
                .wrapping_add(self.q[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.q[index12];
            let h = self.p[(x & 0xff) as usize]
                .wrapping_add(self.p[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.p[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.p[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.q[index]
        };
        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0; 4];

        let mut words = [0u32; 2560];
        for (word, bytes) in words[..8].iter_mut().zip(self.key.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for (word, bytes) in words[8..16].iter_mut().zip(self.iv.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..words.len() {
            let x = words[index - 2];
            let y = words[index - 15];
            words[index] = (x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10))
                .wrapping_add(words[index - 7])
                .wrapping_add(y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3))
                .wrapping_add(words[index - 16])
                .wrapping_add(index as u32);
        }
        self.p.copy_from_slice(&words[512..1536]);
        self.q.copy_from_slice(&words[1536..2560]);
        words.zeroize();
        for _ in 0..4096 {
            self.step();
        }
        self.counter = 0;
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        if self.word_index == 0 {
            self.word = self.step().to_le_bytes();
        }
        let result = self.word[self.word_index];
        self.word_index = (self.word_index + 1) & 3;
        result
    }
}

impl Default for Hc256Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Hc256Engine {
    /// 寫出 `HC-256`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HC-256")
    }
}

impl StreamCipher for Hc256Engine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`。變動時間（查表）。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
    /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，兩者都不改變位置。變動時間
    /// （查表）。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    /// 回到目前金鑰與 IV 的 keystream 開頭。變動時間（重建表時查表）。
    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Hc256Engine {
    type Error = InitError;

    /// 裝入 16 或 32 bytes 的金鑰與至少 16 bytes 的 IV，照 BC 補成 32 bytes；方向不影響，兩個方向用
    /// 同一條 keystream。長度不對時保留原本的金鑰、IV 與位置。變動時間（建表時查表）。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !Self::KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() < Self::MIN_IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        if key.len() == FULL_KEY_BYTES {
            self.key.copy_from_slice(key);
        } else {
            self.key[..key.len()].copy_from_slice(key);
            self.key[key.len()..].copy_from_slice(key);
        }
        let copied = iv.len().min(FULL_IV_BYTES);
        self.iv[..copied].copy_from_slice(&iv[..copied]);
        if copied < FULL_IV_BYTES {
            let remaining = FULL_IV_BYTES - copied;
            self.iv[copied..].copy_from_slice(&iv[..remaining]);
        }
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}

impl Drop for Hc256Engine {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.word.zeroize();
    }
}
