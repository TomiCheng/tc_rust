mod func;
mod mul;
mod table;

pub use func::generate_compact_window_naf;
pub use func::generate_jsf;
pub use func::generate_naf;
pub use func::generate_window_naf;
pub use func::get_naf_weight;
pub use func::get_window_size;
pub use func::wnaf_mul;
pub use func::wnaf_mul_point;
pub use mul::shamirs_trick;
pub use mul::sum_of_multiplies;
pub use mul::sum_of_two_multiplies;
pub use table::WNafTable;

// BC `WNafUtilities.cs:11` 的預設窗寬門檻。
const DEFAULT_WINDOW_SIZE_CUTOFFS: [usize; 6] = [13, 41, 121, 337, 897, 2305];
// 這是 Rust dense 表示使用 `Vec<i8>` 的限制：width > 8 的有號 digit 無法
// 放進 i8；不是 BC 演算法本身的限制（BC 的 dense 編碼型別不同）。
const MAX_DENSE_WIDTH: usize = 8;
// BC `WNafUtilities.cs:11` 的 `MAX_WIDTH`；compact digit 存在 i32 高 16 位。
const MAX_COMPACT_WIDTH: usize = 16;
