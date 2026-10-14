//! 依名稱建立金鑰與演算法參數的產生器，對應 BC 的 `GeneratorUtilities` 與 `ParameterUtilities.GenerateParameters`。
//!
//! 產生器的 `init` 可以不呼叫，沒呼叫時用預設值。

mod algorithms;
mod generator;
mod generator_entry;
mod key_gen_params;
mod table;

pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use generator::Generator;
pub use generator_entry::GeneratorEntry;
pub use key_gen_params::KeyGenParams;
