//! 對應 BC 的 `IEncoder`（輸出寫進 `Stream`）與 `ITranslator`（區塊大小）；
//! `std` 下另可從 `Read` 讀入，BC 沒有這一邊。

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::EncoderError;

/// 二進位資料與 7 位元 ASCII 之間的編碼。
///
/// 實作只需提供長度計算與 slice 進出的 `encode`、`decode`；`alloc`、`std`
/// feature 下的便利方法由預設實作補上。
pub trait Encoder {
    /// 解碼端的一個區塊幾個位元組：Hex 為 1，Base64 為 3。
    const DECODED_BLOCK_SIZE: usize;

    /// 編碼端的一個區塊幾個字元：Hex 為 2，Base64 為 4。
    const ENCODED_BLOCK_SIZE: usize;

    /// `data_len` 個位元組編碼後的長度。
    /// 變動時間：只依長度分支，長度是公開值。
    fn encoded_len(&self, data_len: usize) -> usize;

    /// `encoded_len` 個字元解碼後的長度上限；略過的空白會讓實際長度更短。
    /// 變動時間：只依長度分支，長度是公開值。
    fn decoded_len(&self, encoded_len: usize) -> usize;

    /// 把 `data` 編碼進 `out`，回傳寫入的長度；`out` 不足 `encoded_len` 時回
    /// `BufferTooSmall`。
    /// 常數時間：不依 `data` 的內容分支或查表。
    fn encode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError>;

    /// 把 `data` 解碼進 `out`，回傳寫入的長度。
    /// 常數時間：不依字元值分支或查表；只依空白、填充與長度等公開結構分支。
    fn decode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError>;

    /// 編碼成新的 `Vec`。
    /// 常數時間：同 [`encode`](Self::encode)。
    #[cfg(feature = "alloc")]
    fn encode_to_vec(&self, data: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0; self.encoded_len(data.len())];
        let len = self
            .encode(data, &mut out)
            .expect("encoded_len is large enough");
        out.truncate(len);
        out
    }

    /// 解碼成新的 `Vec`。
    /// 常數時間：同 [`decode`](Self::decode)。
    #[cfg(feature = "alloc")]
    fn decode_to_vec(&self, data: &[u8]) -> Result<Vec<u8>, EncoderError> {
        let mut out = alloc::vec![0; self.decoded_len(data.len())];
        let len = self.decode(data, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// 編碼後寫進 `out`，回傳寫入的長度；對應 BC 的 `Encode(data, Stream)`。
    /// 常數時間：同 [`encode`](Self::encode)；寫入本身的時間由 `out` 決定。
    #[cfg(feature = "std")]
    fn encode_to(&self, data: &[u8], out: &mut dyn std::io::Write) -> std::io::Result<usize> {
        let encoded = self.encode_to_vec(data);
        out.write_all(&encoded)?;
        Ok(encoded.len())
    }

    /// 解碼後寫進 `out`，回傳寫入的長度；對應 BC 的 `Decode(data, Stream)`。
    /// 錯誤以 `InvalidData` 回報。
    /// 常數時間：同 [`decode`](Self::decode)；寫入本身的時間由 `out` 決定。
    #[cfg(feature = "std")]
    fn decode_to(&self, data: &[u8], out: &mut dyn std::io::Write) -> std::io::Result<usize> {
        let decoded = self
            .decode_to_vec(data)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        out.write_all(&decoded)?;
        Ok(decoded.len())
    }

    /// 從 `input` 讀到結尾，編碼後寫進 `out`，回傳寫入的長度。
    /// 常數時間：同 [`encode`](Self::encode)；讀寫本身的時間由 `input`、`out` 決定。
    #[cfg(feature = "std")]
    fn encode_from(
        &self,
        input: &mut dyn std::io::Read,
        out: &mut dyn std::io::Write,
    ) -> std::io::Result<usize> {
        let mut data = Vec::new();
        input.read_to_end(&mut data)?;
        self.encode_to(&data, out)
    }

    /// 從 `input` 讀到結尾，解碼後寫進 `out`，回傳寫入的長度。
    /// 錯誤以 `InvalidData` 回報。
    /// 常數時間：同 [`decode`](Self::decode)；讀寫本身的時間由 `input`、`out` 決定。
    #[cfg(feature = "std")]
    fn decode_from(
        &self,
        input: &mut dyn std::io::Read,
        out: &mut dyn std::io::Write,
    ) -> std::io::Result<usize> {
        let mut data = Vec::new();
        input.read_to_end(&mut data)?;
        self.decode_to(&data, out)
    }
}
