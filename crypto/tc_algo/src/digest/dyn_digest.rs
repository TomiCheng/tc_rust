use tc_digest::Digest;

// 擦除型別用；Send + Sync 讓 AnyDigest 能跨執行緒，clone_box 讓它能 Clone
pub(super) trait DynDigest: Digest + Send + Sync {
    fn clone_box(&self) -> Box<dyn DynDigest>;
}

impl<T: Digest + Clone + Send + Sync + 'static> DynDigest for T {
    fn clone_box(&self) -> Box<dyn DynDigest> {
        todo!()
    }
}
