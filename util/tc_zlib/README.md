# tc_zlib

Pure-Rust port of [zlib v1.3.2](https://github.com/madler/zlib/tree/v1.3.2)
(Jean-loup Gailly & Mark Adler).  No external crates — deflate and inflate are
ported directly from the original C source.

## Usage

### Compression

```rust
use tc_zlib::{ZlibWriter, DeflateOptions, CompressionLevel};
use std::io::Write;

let mut writer = ZlibWriter::compress(Vec::new(), DeflateOptions::default());
writer.write_all(b"hello world").unwrap();
let compressed: Vec<u8> = writer.finish().unwrap();
```

Custom options:

```rust
use tc_zlib::{ZlibWriter, DeflateOptions, CompressionLevel, Strategy};
use std::io::Write;

let opts = DeflateOptions::default()
    .level(CompressionLevel::BestSpeed)
    .strategy(Strategy::Filtered)
    .buf_size(8192);

let mut writer = ZlibWriter::compress(Vec::new(), opts);
writer.write_all(b"hello world").unwrap();
let compressed = writer.finish().unwrap();
```

### Decompression

```rust
use tc_zlib::{ZlibWriter, InflateOptions};
use std::io::Write;

let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
writer.write_all(&compressed).unwrap();
let decompressed: Vec<u8> = writer.finish().unwrap();
```

### Raw deflate (no zlib header)

```rust
use tc_zlib::{ZlibWriter, DeflateOptions, InflateOptions};
use std::io::Write;

// compress without zlib wrapper
let mut writer = ZlibWriter::compress(Vec::new(), DeflateOptions::default().nowrap(true));
writer.write_all(b"hello").unwrap();
let raw = writer.finish().unwrap();

// decompress raw deflate
let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default().nowrap(true));
writer.write_all(&raw).unwrap();
let plain = writer.finish().unwrap();
```

## Options

### `DeflateOptions`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | `CompressionLevel` | `Default` | Compression level (`BestSpeed`, `BestCompression`, `Default`, `None`) |
| `nowrap` | `bool` | `false` | Raw deflate — omit zlib header and trailer |
| `strategy` | `Strategy` | `Default` | Compression strategy (`Default`, `Filtered`, `HuffmanOnly`, `Rle`, `Fixed`) |
| `buf_size` | `usize` | `4096` | Internal output buffer size in bytes |

### `InflateOptions`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `nowrap` | `bool` | `false` | Raw deflate — expect no zlib header or trailer |
| `buf_size` | `usize` | `4096` | Internal output buffer size in bytes |

## References

- [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950) — zlib format
- [RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951) — deflate format
- [zlib v1.3.2 source](https://github.com/madler/zlib/tree/v1.3.2)
