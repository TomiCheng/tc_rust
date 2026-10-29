// This crate is a Rust port of zlib 1.3.2 and has been altered from the
// original C source. The zlib license applies to the ported code:
//
//   (C) 1995-2026 Jean-loup Gailly and Mark Adler
//
//   This software is provided 'as-is', without any express or implied
//   warranty.  In no event will the authors be held liable for any damages
//   arising from the use of this software.
//
//   Permission is granted to anyone to use this software for any purpose,
//   including commercial applications, and to alter it and redistribute it
//   freely, subject to the following restrictions:
//
//   1. The origin of this software must not be misrepresented; you must not
//      claim that you wrote the original software. If you use this software
//      in a product, an acknowledgment in the product documentation would be
//      appreciated but is not required.
//   2. Altered source versions must be plainly marked as such, and must not be
//      misrepresented as being the original software.
//   3. This notice may not be removed or altered from any source distribution.
//
//   Jean-loup Gailly        Mark Adler
//   jloup@gzip.org          madler@alumni.caltech.edu

//! Zlib 與 raw deflate 壓縮，從 zlib 1.3.2 移植，對應 Bouncy Castle 的
//! `Utilities.Zlib`。
//!
//! 壓縮與解壓都依資料內容分支，全部是變動時間，只能用於公開值；壓縮過的秘密資料
//! 會從長度洩漏內容（CRIME、BREACH 一類的攻擊）。
//!
//! | 型別 | 用途 |
//! |------|------|
//! | [`ZlibWriter`] | 包住 `Write`，在 `write()` 時壓縮或解壓 |
//! | [`ZlibReader`] | 包住 `Read`，在 `read()` 時壓縮或解壓 |
//!
//! 兩者都在建構時選擇壓縮（deflate）或解壓（inflate），對應 BC 的
//! `ZOutputStream` 與 `ZInputStream` 以 `compress` 旗標切換兩種模式。
//!
//! ```
//! use std::io::Write;
//!
//! use tc_zlib::{DeflateOptions, InflateOptions, ZlibWriter};
//!
//! let mut writer = ZlibWriter::compress(Vec::new(), DeflateOptions::default());
//! writer.write_all(b"hello world").unwrap();
//! let compressed = writer.finish().unwrap();
//!
//! let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
//! writer.write_all(&compressed).unwrap();
//! assert_eq!(writer.finish().unwrap(), b"hello world");
//! ```

mod adler32;
mod constants;
mod deflate;
mod deflate_options;
mod inflate;
mod inflate_options;
mod stream;
mod zlib_reader;
mod zlib_writer;

pub use constants::{CompressionLevel, FlushMode, Strategy};
pub use deflate_options::DeflateOptions;
pub use inflate_options::InflateOptions;
pub use zlib_reader::ZlibReader;
pub use zlib_writer::ZlibWriter;
