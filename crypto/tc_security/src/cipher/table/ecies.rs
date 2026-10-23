//! ECIES：BC `CipherUtilities.GetCipher("ECIES")` 的組合，ECDH 加 KDF2(SHA-1) 與 HMAC(SHA-1)，XOR 加密。
//! BC C# 的 `BufferedIesCipher` 還沒實作 `Init`；這裡照它的結構補上：輸入全部存起來，`do_final`
//! 時整則交給 IES engine。參數用 [`AnyParams::Ies`]。

use std::convert::Infallible;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_ies::{IesEngine, IesParamsRef};
use tc_kdf::Kdf2;
use tc_macs::{Hmac, Mac};
use tc_zeroize::Zeroize;

use super::specs::{Lengths, StandaloneSpec};
use crate::agreement::{self, AnyAgreement};
use crate::cipher::{Algorithm, AnyCipher};
use crate::digest::{self, AnyDigest};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 沒有模式與 padding；金鑰在 [`AnyParams::Ies`] 裡，沒有對稱金鑰可產生。
pub(super) const ECIES: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Ecies,
    names: &["ECIES"],
    key: Lengths::exact(0),
    cipher: || AnyCipher::new(BufferedIes::new()),
    oids: &[],
};

type Engine = IesEngine<AnyAgreement, Kdf2<AnyDigest>, Hmac<AnyDigest>>;

/// BC 的 `BufferedIesCipher`：`process_bytes` 只收進緩衝區，`do_final` 才加密或解密整則訊息。
struct BufferedIes {
    engine: Engine,
    mac_size: usize,
    direction: Option<CipherDirection>,
    buffer: Vec<u8>,
}

impl BufferedIes {
    fn new() -> Self {
        let agreement = agreement::get_by_name("ECDH")
            .expect("the ecies feature turns on ec, which has ECDH")
            .agreement();
        let mac = Hmac::new(digest::get(digest::Algorithm::Sha1));
        let mac_size = mac.mac_size();
        Self {
            engine: IesEngine::new(
                agreement,
                Kdf2::new(digest::get(digest::Algorithm::Sha1)),
                mac,
            ),
            mac_size,
            direction: None,
            buffer: Vec::new(),
        }
    }

    fn direction(&self) -> Result<CipherDirection, AnyError> {
        self.direction
            .ok_or_else(|| AnyError::new(BufferedError::<Infallible>::NotInitialized))
    }
}

impl BufferedCipherInit<AnyParams> for BufferedIes {
    type Error = AnyError;

    /// 收 [`AnyParams::Ies`]：自己的私鑰與對方的公鑰算出共享秘密，丟掉緩衝區裡還沒處理的輸入。
    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), AnyError> {
        self.direction = None;
        self.buffer.zeroize();
        let AnyParams::Ies {
            private_key,
            public_key,
            derivation_v,
            encoding_v,
            mac_key_bits,
        } = params
        else {
            return Err(AnyError::new(SecurityError::WrongParams));
        };
        self.engine
            .init(
                direction.into(),
                &**private_key,
                &**public_key,
                &IesParamsRef::new(derivation_v, encoding_v, *mac_key_bits),
            )
            .map_err(AnyError::new)?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl BufferedCipher for BufferedIes {
    type Error = AnyError;

    /// 不是分組加密，同 BC 回傳 0。
    fn block_size(&self) -> usize {
        0
    }

    /// 輸入都留到 `do_final`，所以中途不會輸出。
    fn update_output_len(&self, _input_len: usize) -> Result<usize, AnyError> {
        self.direction()?;
        Ok(0)
    }

    /// 加密多一個 MAC，解密少一個 MAC；XOR 加密的密文與明文一樣長，所以是確切的長度。
    fn output_len(&self, input_len: usize) -> Result<usize, AnyError> {
        let total = self
            .buffer
            .len()
            .checked_add(input_len)
            .ok_or_else(|| AnyError::new(BufferedError::<Infallible>::InputTooLong))?;
        Ok(match self.direction()? {
            CipherDirection::Encrypt => total + self.mac_size,
            CipherDirection::Decrypt => total.saturating_sub(self.mac_size),
        })
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, AnyError> {
        self.direction()?;
        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    /// 輸出太短時不處理、保留緩衝區；其餘情況處理完都清空緩衝區，下一則訊息沿用同一組金鑰。
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AnyError> {
        let required = self.output_len(0)?;
        if output.len() < required {
            return Err(AnyError::new(BufferedError::<Infallible>::OutputTooShort {
                required,
                available: output.len(),
            }));
        }
        let result = self.engine.process_block(&self.buffer);
        self.buffer.zeroize();
        let mut result = result.map_err(AnyError::new)?;
        let len = result.len();
        output[..len].copy_from_slice(&result);
        result.zeroize();
        Ok(len)
    }

    fn reset(&mut self) {
        self.buffer.zeroize();
    }
}

impl Drop for BufferedIes {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}
