use crate::private_key_info::PrivateKeyInfoProvider;
use crate::spki::SpkiProvider;

// tc_algo 與 ASN.1 之間的轉換；各類轉換的 provider 之後加在這裡
pub trait AlgoAsn1: Send + Sync {
    fn spki(&self) -> &dyn SpkiProvider;

    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider;
}
