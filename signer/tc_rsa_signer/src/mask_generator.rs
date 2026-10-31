use alloc::vec;
use tc_digest::{Digest, Xof};

/// PSS 的遮罩產生函式：由 `seed` 填滿 `mask`。BC 依 MGF 的雜湊是否為 XOF 在執行期選擇，
/// 這裡由型別選定：[`Mgf1`] 或 [`XofMgf`]。
pub trait MaskGenerator {
    /// 以 `seed` 填滿 `mask`。本 crate 的兩個實作是常數時間，程度同它們的雜湊。
    fn generate(&mut self, seed: &[u8], mask: &mut [u8]);
}

/// RFC 8017 B.2.1 的 MGF1：H(seed ‖ C) 依大端序 32 位元計數 C 串接，截到所需長度。
pub struct Mgf1<D> {
    digest: D,
}

impl<D> Mgf1<D> {
    /// 以 `digest` 為雜湊的 MGF1。常數時間。
    pub fn new(digest: D) -> Self {
        Self { digest }
    }
}

impl<D: Digest> MaskGenerator for Mgf1<D> {
    /// BC 的 `MaskGeneratorFunction1`。常數時間程度同雜湊：只依長度迴圈。
    fn generate(&mut self, seed: &[u8], mask: &mut [u8]) {
        self.digest.reset();
        let mut block = vec![0u8; self.digest.digest_size()];
        for (counter, chunk) in (0u32..).zip(mask.chunks_mut(block.len())) {
            self.digest.update(seed);
            self.digest.update(&counter.to_be_bytes());
            self.digest.do_final(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// 以 XOF 為遮罩，RFC 8702 以 SHAKE 用於 PSS 時的作法：XOF(seed) 的前段。
pub struct XofMgf<X> {
    xof: X,
}

impl<X> XofMgf<X> {
    /// 以 `xof` 為遮罩產生函式。常數時間。
    pub fn new(xof: X) -> Self {
        Self { xof }
    }
}

impl<X: Xof> MaskGenerator for XofMgf<X> {
    /// BC 的 `MaskGeneratorFunction` 遇到 `IXof` 時的作法。常數時間程度同 XOF。
    fn generate(&mut self, seed: &[u8], mask: &mut [u8]) {
        self.xof.reset();
        self.xof.update(seed);
        self.xof.output_final(mask);
    }
}
