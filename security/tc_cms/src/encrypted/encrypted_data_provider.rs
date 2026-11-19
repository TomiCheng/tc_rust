use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_asn1_x500::Attribute;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::encrypted::CmsEncryptedData;

pub trait EncryptedDataProvider: Send + Sync {
    // 以 key（KeyOwned）與亂數 IV 加密內容，內容型別是 id-data；encryption 是 AES-128／192／256-CBC
    // 或 DES-EDE3-CBC 的 OID，key 的長度要合它，否則是 InvalidKey。unprotected 寫成
    // unprotectedAttrs，沒有就不寫
    fn generate(
        &self,
        content: &[u8],
        encryption: &Asn1Oid,
        key: &dyn Params,
        unprotected: Vec<Attribute>,
    ) -> Result<CmsEncryptedData, CmsError>;

    // key 是 KeyOwned，其他型別是 WrongRecipientKey；RC2-CBC 的舊訊息也解得開
    fn decrypt(
        &self,
        data: &CmsEncryptedData,
        key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError>;
}
