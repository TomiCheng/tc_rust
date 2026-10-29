//! Options for zlib compression (deflate).

use super::constants::{CompressionLevel, Strategy};

/// Options for compression (deflate).
///
/// Used with [`ZlibWriter::compress`](crate::ZlibWriter::compress) and
/// [`ZlibReader::compress`](crate::ZlibReader::compress).
///
/// # Examples
///
/// ```
/// use tc_zlib::{DeflateOptions, CompressionLevel, Strategy};
///
/// // default: level 6, zlib-wrapped, default strategy, 4096-byte buffer
/// let opts = DeflateOptions::default();
/// assert_eq!(opts.level, CompressionLevel::Default);
/// assert!(!opts.nowrap);
/// assert_eq!(opts.strategy, Strategy::Default);
/// assert_eq!(opts.buf_size, 4096);
///
/// // builder style
/// let opts = DeflateOptions::default()
///     .level(CompressionLevel::BestSpeed)
///     .nowrap(true)
///     .strategy(Strategy::Filtered)
///     .buf_size(8192);
/// assert_eq!(opts.level, CompressionLevel::BestSpeed);
/// assert!(opts.nowrap);
/// assert_eq!(opts.strategy, Strategy::Filtered);
/// assert_eq!(opts.buf_size, 8192);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflateOptions {
    /// Compression level.
    pub level: CompressionLevel,
    /// If `true`, omit the zlib header and trailer (raw deflate stream).
    pub nowrap: bool,
    /// Compression strategy.
    pub strategy: Strategy,
    /// Size of the internal output buffer in bytes (default: 4096).
    pub buf_size: usize,
}

impl Default for DeflateOptions {
    /// Returns default options: `CompressionLevel::Default`, zlib-wrapped, `Strategy::Default`, 4096-byte buffer.
    fn default() -> Self {
        Self {
            level: CompressionLevel::Default,
            nowrap: false,
            strategy: Strategy::Default,
            buf_size: 4096,
        }
    }
}

impl DeflateOptions {
    /// Sets the compression level.
    /// 變動時間：不讀任何資料。
    pub fn level(mut self, level: CompressionLevel) -> Self {
        self.level = level;
        self
    }

    /// Sets whether to omit the zlib header and trailer (raw deflate stream).
    /// 變動時間：不讀任何資料。
    pub fn nowrap(mut self, nowrap: bool) -> Self {
        self.nowrap = nowrap;
        self
    }

    /// Sets the compression strategy.
    /// 變動時間：不讀任何資料。
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
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
