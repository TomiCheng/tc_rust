use tc_zeroize::Zeroize;

/// cipher、MAC 與 key wrapper 共用的參數，每個 variant 對應 BC 的一個參數類別。
///
/// 只是 DTO，不驗證內容：長度與組合合不合用，由收到參數的 cipher 在 `init` 判定。
/// 各引擎的參數 trait 依 variant 取值，這個 variant 沒有的值回傳空的或預設值，留給 `init` 拒絕。
/// drop 時清除金鑰、IV、nonce 與 AAD。
#[derive(Clone)]
pub enum AnyParams {
    /// 只有金鑰，對應 BC 的 `KeyParameter`。
    Key { key: Vec<u8> },
    /// 在內層參數外加上 IV，對應 BC 的 `ParametersWithIV`；內層通常是 `Key`、`Rc2` 或 `Rc5`。
    WithIv {
        parameters: Box<AnyParams>,
        iv: Vec<u8>,
    },
    /// AEAD 的參數，對應 BC 的 `AeadParameters`；`mac_size` 同 BC 以 bit 計。
    Aead {
        key: Vec<u8>,
        mac_size: usize,
        nonce: Vec<u8>,
        associated_text: Vec<u8>,
    },
    /// RC2 的金鑰與有效金鑰位元數，對應 BC 的 `RC2Parameters`。
    Rc2 {
        key: Vec<u8>,
        effective_key_bits: usize,
    },
    /// RC5 的金鑰與輪數，對應 BC 的 `RC5Parameters`。
    Rc5 { key: Vec<u8>, rounds: usize },
}

impl AnyParams {
    /// 只有金鑰的參數，同 BC 的 `new KeyParameter(key)`。
    pub fn new(key: Vec<u8>) -> Self {
        Self::Key { key }
    }

    /// 在這組參數外加上 IV，同 BC 的 `new ParametersWithIV(parameters, iv)`。
    pub fn with_iv(self, iv: Vec<u8>) -> Self {
        Self::WithIv {
            parameters: Box::new(self),
            iv,
        }
    }

    /// AEAD 的參數，同 BC 的 `new AeadParameters(key, macSize, nonce, associatedText)`；`mac_size` 以 bit 計。
    pub fn aead(key: Vec<u8>, mac_size: usize, nonce: Vec<u8>, associated_text: Vec<u8>) -> Self {
        Self::Aead {
            key,
            mac_size,
            nonce,
            associated_text,
        }
    }

    /// RC2 的參數，同 BC 的 `new RC2Parameters(key, bits)`。
    pub fn rc2(key: Vec<u8>, effective_key_bits: usize) -> Self {
        Self::Rc2 {
            key,
            effective_key_bits,
        }
    }

    /// RC5 的參數，同 BC 的 `new RC5Parameters(key, rounds)`。
    pub fn rc5(key: Vec<u8>, rounds: usize) -> Self {
        Self::Rc5 { key, rounds }
    }

    // 金鑰在最內層：WithIv 往內找
    fn key_bytes(&self) -> &[u8] {
        match self {
            Self::Key { key }
            | Self::Aead { key, .. }
            | Self::Rc2 { key, .. }
            | Self::Rc5 { key, .. } => key,
            Self::WithIv { parameters, .. } => parameters.key_bytes(),
        }
    }

    // 只有最外層的 WithIv 帶 IV
    fn iv_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::WithIv { iv, .. } => Some(iv),
            _ => None,
        }
    }
}

impl Drop for AnyParams {
    fn drop(&mut self) {
        match self {
            Self::Key { key } | Self::Rc2 { key, .. } | Self::Rc5 { key, .. } => key.zeroize(),
            // 內層的參數在自己 drop 時清除
            Self::WithIv { iv, .. } => iv.zeroize(),
            Self::Aead {
                key,
                nonce,
                associated_text,
                ..
            } => {
                key.zeroize();
                nonce.zeroize();
                associated_text.zeroize();
            }
        }
    }
}

// block cipher 與 block mode

impl tc_block_cipher::KeyParams for AnyParams {
    fn key(&self) -> &[u8] {
        self.key_bytes()
    }
}

impl tc_block_modes::IvParams for AnyParams {
    fn iv(&self) -> &[u8] {
        self.iv_bytes().unwrap_or_default()
    }
}

// key wrap：沒給 IV 時由 wrapper 用規格的預設值（例如 RFC 3394 的 A6A6…）
impl tc_key_wrap::IvOptParams for AnyParams {
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv_bytes()
    }
}

// AEAD 只接受 `Aead`：tag 長度與 nonce 一定由呼叫端明確給。BC 的 AEAD 也收 `ParametersWithIV`，
// 但沒給的 tag 長度要靠預設值，而各模式、各函式庫的預設不同（BC 的 CCM 8 bytes、OpenSSL 12 bytes），
// 加解密兩端會對不上；所以其他 variant 回報空的 nonce 與 0 的 tag 長度，讓 init 拒絕

impl tc_aead_cipher::NonceParams for AnyParams {
    fn nonce(&self) -> &[u8] {
        match self {
            Self::Aead { nonce, .. } => nonce,
            _ => &[],
        }
    }
}

impl tc_aead_cipher::MacSizeParams for AnyParams {
    // AEAD 的契約以 byte 計：不是整數個 byte 的長度回傳 0，讓 init 拒絕
    fn mac_size(&self) -> usize {
        match self {
            Self::Aead { mac_size, .. } if mac_size % 8 == 0 => mac_size / 8,
            _ => 0,
        }
    }
}

impl tc_aead_cipher::InitialAadParams for AnyParams {
    fn initial_aad(&self) -> &[u8] {
        match self {
            Self::Aead {
                associated_text, ..
            } => associated_text,
            _ => &[],
        }
    }
}

// stream cipher：跟 block cipher 是不同的 trait

impl tc_stream_cipher::KeyParams for AnyParams {
    fn key(&self) -> &[u8] {
        self.key_bytes()
    }
}

impl tc_stream_cipher::IvParams for AnyParams {
    fn iv(&self) -> &[u8] {
        self.iv_bytes().unwrap_or_default()
    }
}

// RC2、RC5 的專用參數

#[cfg(feature = "rc2")]
impl tc_rc_cipher::Rc2Params for AnyParams {
    fn effective_key_bits(&self) -> usize {
        match self {
            Self::Rc2 {
                effective_key_bits, ..
            } => *effective_key_bits,
            Self::WithIv { parameters, .. } => parameters.effective_key_bits(),
            // 沒給時用整把金鑰的長度，超過 128 bytes 就用上限 1024 bits，同 BC 的 `RC2Parameters(key)`
            _ => {
                let key = self.key_bytes();
                if key.len() > tc_rc_cipher::RC2_MAX_KEY_BYTES {
                    tc_rc_cipher::RC2_MAX_EFFECTIVE_KEY_BITS
                } else {
                    key.len() * 8
                }
            }
        }
    }
}

#[cfg(feature = "rc5")]
impl tc_rc_cipher::Rc5Params for AnyParams {
    fn rounds(&self) -> usize {
        match self {
            Self::Rc5 { rounds, .. } => *rounds,
            Self::WithIv { parameters, .. } => parameters.rounds(),
            // 沒給時用 12 輪，同 BC
            _ => tc_rc_cipher::RC5_DEFAULT_ROUNDS,
        }
    }
}
