/// BC 的 `Gost3410ValidationParameters`：產生參數時的起點 x0 與增量 c，可用來重現 p 與 q。
/// 程序 1 用 32 位元的值，程序 2 用 64 位元的值，另一組為 0，同 BC。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gost3410ValidationParameters {
    x0: i32,
    c: i32,
    x0_long: i64,
    c_long: i64,
}

impl Gost3410ValidationParameters {
    /// 程序 1 的 x0 與 c。常數時間。
    pub fn new(x0: i32, c: i32) -> Self {
        Self {
            x0,
            c,
            x0_long: 0,
            c_long: 0,
        }
    }

    /// 程序 2 的 x0 與 c。常數時間。
    pub fn new_long(x0: i64, c: i64) -> Self {
        Self {
            x0: 0,
            c: 0,
            x0_long: x0,
            c_long: c,
        }
    }

    /// 程序 1 的 x0。常數時間。
    pub fn x0(&self) -> i32 {
        self.x0
    }

    /// 程序 1 的 c。常數時間。
    pub fn c(&self) -> i32 {
        self.c
    }

    /// 程序 2 的 x0。常數時間。
    pub fn x0_long(&self) -> i64 {
        self.x0_long
    }

    /// 程序 2 的 c。常數時間。
    pub fn c_long(&self) -> i64 {
        self.c_long
    }
}
