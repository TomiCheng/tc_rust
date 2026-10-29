//! Zlib constants — port of `JZlib.cs` and `zlib.h`.

/// Compression level for deflate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression — input is copied as-is (`Z_NO_COMPRESSION = 0`).
    None,
    /// Optimise for speed (`Z_BEST_SPEED = 1`).
    BestSpeed,
    /// Optimise for compression ratio (`Z_BEST_COMPRESSION = 9`).
    BestCompression,
    /// Default compromise between speed and ratio (`Z_DEFAULT_COMPRESSION`).
    Default,
}

/// Compression strategy for deflate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Default strategy for general data (`Z_DEFAULT_STRATEGY`).
    Default,
    /// Tuned for data produced by a filter or predictor, e.g. PNG (`Z_FILTERED`).
    Filtered,
    /// Force Huffman encoding only, no string matching (`Z_HUFFMAN_ONLY`).
    HuffmanOnly,
    /// Limit match distances to one — run-length encoding (`Z_RLE`).
    Rle,
    /// Use fixed Huffman codes (`Z_FIXED`).
    Fixed,
}

/// Flush mode for `deflate` / `inflate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMode {
    /// Let the library decide when to produce output (`Z_NO_FLUSH`).
    NoFlush,
    /// Flush all pending output, aligned to a byte boundary (`Z_SYNC_FLUSH`).
    SyncFlush,
    /// Flush and reset compression state (`Z_FULL_FLUSH`).
    FullFlush,
    /// Finish the stream and produce all remaining output (`Z_FINISH`).
    Finish,
}
