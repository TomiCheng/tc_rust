//! CMS 的簽章、加密與 MAC 資料，對應 Bouncy Castle 的 `Org.BouncyCastle.Cms`。

mod algorithms;
pub mod auth_enveloped;
pub mod authenticated;
pub mod compressed;
mod default_cms_operator;
mod default_cms_operator_builder;
mod der;
pub mod digested;
pub mod encrypted;
pub mod enveloped;
mod error;
pub mod signed;
mod stream;
mod traits;

pub use default_cms_operator_builder::DefaultCmsOperatorBuilder;
pub use error::CmsError;
pub use traits::{CmsOperator, CmsOperatorBuilder};
