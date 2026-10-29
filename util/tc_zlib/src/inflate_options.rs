//! Options for zlib decompression (inflate).

/// Options for decompression (inflate).
///
/// Used with [`ZlibWriter::decompress`](crate::ZlibWriter::decompress) and
/// [`ZlibReader::decompress`](crate::ZlibReader::decompress).
///
/// # Examples
///
/// ```
/// use tc_zlib::InflateOptions;
///
/// // default: zlib-wrapped stream, 4096-byte buffer
/// let opts = InflateOptions::default();
/// assert!(!opts.nowrap);
/// assert_eq!(opts.buf_size, 4096);
///
/// // builder style
/// let raw = InflateOptions::default().nowrap(true).buf_size(8192);
/// assert!(raw.nowrap);
/// assert_eq!(raw.buf_size, 8192);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflateOptions {
    /// If `true`, expect a raw deflate stream with no zlib header or trailer.
    pub nowrap: bool,
    /// Size of the internal output buffer in bytes (default: 4096).
    pub buf_size: usize,
}

impl Default for InflateOptions {
    /// Returns default options: zlib-wrapped stream, 4096-byte buffer.
    fn default() -> Self {
        Self {
            nowrap: false,
            buf_size: 4096,
        }
    }
}

impl InflateOptions {
    /// Sets whether to expect a raw deflate stream (no zlib header or trailer).
    /// 變動時間：不讀任何資料。
    pub fn nowrap(mut self, nowrap: bool) -> Self {
        self.nowrap = nowrap;
        self
    }

    /// Sets the size of the internal output buffer in bytes.
    ///
    /// Larger buffers reduce the number of calls to the inner writer but use more memory.
    /// Must be greater than zero.
    /// 變動時間：不讀任何資料。
    pub fn buf_size(mut self, buf_size: usize) -> Self {
        self.buf_size = buf_size;
        self
    }
}
