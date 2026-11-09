/// BC 的 `Adrs`：FIPS 205 的 32 位元組位址。
#[derive(Clone, Copy, Default)]
pub(crate) struct Adrs(pub(crate) [u8; 32]);

pub(crate) const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
pub(crate) const TREE: u32 = 2;
pub(crate) const FORS_TREE: u32 = 3;
pub(crate) const FORS_PK: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
pub(crate) const FORS_PRF: u32 = 6;

impl Adrs {
    fn put(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn set_layer(&mut self, layer: u32) {
        self.put(0, layer);
    }

    pub(crate) fn set_tree(&mut self, tree: u64) {
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// 設定型別並清掉後面的 12 位元組，FIPS 205 的 setTypeAndClear。
    pub(crate) fn set_type_and_clear(&mut self, kind: u32) {
        self.put(16, kind);
        self.0[20..].fill(0);
    }

    /// 只改型別，BC 的 `SetType`。
    pub(crate) fn set_type(&mut self, kind: u32) {
        self.put(16, kind);
    }

    pub(crate) fn set_key_pair(&mut self, index: u32) {
        self.put(20, index);
    }

    pub(crate) fn key_pair(&self) -> u32 {
        u32::from_be_bytes(self.0[20..24].try_into().expect("4 bytes"))
    }

    pub(crate) fn set_chain(&mut self, index: u32) {
        self.put(24, index);
    }

    pub(crate) fn set_hash(&mut self, index: u32) {
        self.put(28, index);
    }

    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.put(24, height);
    }

    pub(crate) fn set_tree_index(&mut self, index: u32) {
        self.put(28, index);
    }

    pub(crate) fn tree_index(&self) -> u32 {
        u32::from_be_bytes(self.0[28..32].try_into().expect("4 bytes"))
    }

    /// SHA2 參數組用的 22 位元組壓縮位址。
    pub(crate) fn compressed(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.0[3];
        out[1..9].copy_from_slice(&self.0[8..16]);
        out[9] = self.0[19];
        out[10..].copy_from_slice(&self.0[20..]);
        out
    }
}
