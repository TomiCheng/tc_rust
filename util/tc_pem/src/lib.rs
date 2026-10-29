//! PEM 編碼與解碼，對應 Bouncy Castle 的 `Utilities.IO.Pem`。
//!
//! 內文常是私鑰：base64 編碼與解碼走常數時間，[`PemObject`] 的內容與讀取時的暫存
//! 在 drop 時清除。外框與標頭視為公開值。寫出時換行固定是 LF。
//!
//! ```
//! use tc_pem::{PemObject, PemReader, PemWriter};
//!
//! let key = PemObject::new("PRIVATE KEY", vec![0x30, 0x03, 0x02, 0x01, 0x00]);
//! let mut writer = PemWriter::new(Vec::new());
//! writer.write_object(&key).unwrap();
//! let pem = writer.into_inner();
//!
//! let mut reader = PemReader::new(&pem[..]);
//! let read = reader.read_pem_object().unwrap().unwrap();
//! assert_eq!(read.content(), key.content());
//! ```
//!
//! | bc-csharp | tc_pem |
//! |-----------|--------|
//! | `PemGenerationException.cs` | [`PemGenerationError`] |
//! | `PemHeader.cs` | [`PemHeader`] |
//! | `PemObject.cs` | [`PemObject`] |
//! | `PemObjectGenerator.cs` | [`PemObjectGenerator`] |
//! | `PemObjectParser.cs` | [`PemObjectParser`] |
//! | `PemReader.cs` | [`PemReader`] |
//! | `PemWriter.cs` | [`PemWriter`] |

mod errors;
mod pem_header;
mod pem_object;
mod pem_reader;
mod pem_writer;
mod traits;

pub use errors::PemGenerationError;
pub use pem_header::PemHeader;
pub use pem_object::PemObject;
pub use pem_reader::PemReader;
pub use pem_writer::PemWriter;
pub use traits::{PemObjectGenerator, PemObjectParser};
