/// 每次產生一個位於 `[1, n - 1]` 的 ECDSA 暫時純量。
pub trait KCalculator<S> {
    /// 是否由私鑰與訊息決定輸出。
    fn is_deterministic(&self) -> bool;

    /// 產生下一個有效暫時純量。
    fn next_k(&mut self) -> S;
}
