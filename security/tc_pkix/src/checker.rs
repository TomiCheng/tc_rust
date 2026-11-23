use std::collections::BTreeSet;

use tc_asn1::Asn1Oid;
use tc_x509::cert::X509Certificate;

use crate::PkixError;

// BC 的 PkixCertPathChecker：路徑上的每張憑證逐一交給它，處理掉的關鍵擴充要從 unresolved 移除。
// 方法取 &self，參數因此可以共用；需要狀態的實作自己用內部可變性
pub trait CertPathChecker: Send + Sync {
    // 每次驗證開始時呼叫；forward 是從終端往信任錨的方向
    fn init(&self, forward: bool) -> Result<(), PkixError>;

    fn is_forward_checking_supported(&self) -> bool;

    fn supported_extensions(&self) -> BTreeSet<Asn1Oid>;

    fn check(
        &self,
        certificate: &X509Certificate,
        unresolved_critical_extensions: &mut BTreeSet<Asn1Oid>,
    ) -> Result<(), PkixError>;
}
