use std::any::Any;
use std::sync::Arc;

use tc_algo::Params;
use tc_x509::cert::X509Certificate;

// 解開 KeyAgree 收件人用的金鑰：EC 私鑰與它的憑證。憑證用來找出自己的 RecipientEncryptedKey，
// 並給出曲線，好讀寄件人的臨時公鑰，同 BC 以私鑰的 PrivateKeyInfo 演算法讀它
pub struct KeyAgreeKey {
    private_key: Arc<dyn Params>,
    certificate: X509Certificate,
}

impl KeyAgreeKey {
    pub fn new(private_key: Arc<dyn Params>, certificate: X509Certificate) -> Self {
        Self {
            private_key,
            certificate,
        }
    }

    pub fn private_key(&self) -> &dyn Params {
        self.private_key.as_ref()
    }

    pub fn certificate(&self) -> &X509Certificate {
        &self.certificate
    }
}

impl Params for KeyAgreeKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
