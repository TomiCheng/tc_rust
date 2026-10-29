//! Hex、Base64 與 UrlBase64 編碼，移植自 Bouncy Castle 的 `Utilities.Encoders`。
//!
//! 每種編碼都實作 [`Encoder`]，編碼與解碼對資料內容是常數時間，可以處理金鑰
//! 這類秘密值。
//!
//! 不開 feature 時以 slice 進出：
//!
//! ```
//! use tc_encoders::Encoder;
//! use tc_encoders::{base64, hex::Hex};
//!
//! let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];
//!
//! let mut text = [0; 16];
//! let len = Hex::LOWER.encode(&key, &mut text)?;
//! assert_eq!(&text[..len], b"2b7e151628aed2a6");
//!
//! let mut text = [0; 12];
//! let len = base64::DEFAULT.encode(&key, &mut text)?;
//! assert_eq!(&text[..len], b"K34VFiiu0qY=");
//!
//! let mut back = [0; 8];
//! let len = base64::DEFAULT.decode(&text[..len], &mut back)?;
//! assert_eq!(back[..len], key);
//! # Ok::<(), tc_encoders::EncoderError>(())
//! ```
//!
//! `alloc` feature 加上回傳 `Vec` 的方法；`std` feature 再加上寫進 `Write` 的
//! `encode_to`、`decode_to`，以及從 `Read` 讀入的 `encode_from`、`decode_from`：
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn main() -> std::io::Result<()> {
//! use std::io::Write;
//!
//! use tc_encoders::Encoder;
//! use tc_encoders::base64;
//!
//! let mut token: Vec<u8> = Vec::new();
//! base64::RFC4648_URL_NO_PAD.encode_to(b"{\"alg\":\"none\"}", &mut token)?;
//! token.write_all(b".")?;
//! base64::RFC4648_URL_NO_PAD.encode_to(b"{\"sub\":\"42\"}", &mut token)?;
//! assert_eq!(token, b"eyJhbGciOiJub25lIn0.eyJzdWIiOiI0MiJ9");
//!
//! let mut json = Vec::new();
//! base64::RFC4648_URL_NO_PAD.decode_to(b"eyJzdWIiOiI0MiJ9", &mut json)?;
//! assert_eq!(json, b"{\"sub\":\"42\"}");
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```
//!
//! 資料分段到達時，`std` 下的 `EncoderWriter` 本身就是 `Write`，邊寫邊編碼，
//! `finish` 時補上最後一組與填充；反方向的 `DecoderReader` 本身就是 `Read`，邊讀
//! 邊解碼：
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn main() -> std::io::Result<()> {
//! use std::io::{Read, Write};
//!
//! use tc_encoders::{DecoderReader, EncoderWriter, base64};
//!
//! let mut writer = EncoderWriter::new(base64::DEFAULT, Vec::new());
//! for part in [&b"Many "[..], b"hands ", b"make light work."] {
//!     writer.write_all(part)?;
//! }
//! let text = writer.finish()?;
//! assert_eq!(text, b"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
//!
//! let mut reader = DecoderReader::new(base64::DEFAULT, &text[..]);
//! let mut back = String::new();
//! reader.read_to_string(&mut back)?;
//! assert_eq!(back, "Many hands make light work.");
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod base64;
mod errors;
pub mod hex;
#[cfg(feature = "std")]
mod io;
mod traits;
mod whitespace;

pub use errors::EncoderError;
#[cfg(feature = "std")]
pub use io::{DecoderReader, EncoderWriter};
pub use traits::Encoder;
