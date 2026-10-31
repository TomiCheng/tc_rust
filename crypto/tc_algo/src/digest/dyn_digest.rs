use tc_digest::Digest;

// For type erasure: Send + Sync let AnyDigest cross threads, and clone_box lets it be cloned
pub(super) trait DynDigest: Digest + Send + Sync {
    fn clone_box(&self) -> Box<dyn DynDigest>;
}

impl<T: Digest + Clone + Send + Sync + 'static> DynDigest for T {
    fn clone_box(&self) -> Box<dyn DynDigest> {
        Box::new(self.clone())
    }
}
