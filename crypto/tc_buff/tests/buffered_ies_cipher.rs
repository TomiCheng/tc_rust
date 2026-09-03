use core::fmt;

use tc_buff::BufferedIesCipher;
use tc_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection, IesCipher, IesCipherInit,
};
use tc_crypto::AlgorithmName;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestError {
    InvalidCiphertext,
}

impl fmt::Display for TestError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("invalid IES ciphertext")
    }
}

impl core::error::Error for TestError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestInitError;

impl fmt::Display for TestInitError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("invalid IES key")
    }
}

impl core::error::Error for TestInitError {}

struct Params {
    mask: u8,
}

struct TestIesEngine {
    direction: CipherDirection,
    mask: u8,
}

impl TestIesEngine {
    const TAG: [u8; 2] = [0xa5, 0x5a];

    const fn new() -> Self {
        Self {
            direction: CipherDirection::Encrypt,
            mask: 0,
        }
    }
}

impl AlgorithmName for TestIesEngine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("TestIES")
    }
}

impl IesCipher for TestIesEngine {
    type Error = TestError;

    fn get_output_size(&self, input_len: usize) -> usize {
        match self.direction {
            CipherDirection::Encrypt => input_len.saturating_add(Self::TAG.len()),
            CipherDirection::Decrypt => input_len.saturating_sub(Self::TAG.len()),
        }
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            CipherDirection::Encrypt => {
                for (source, target) in input.iter().zip(output.iter_mut()) {
                    *target = *source ^ self.mask;
                }
                let end = input.len() + Self::TAG.len();
                output[input.len()..end].copy_from_slice(&Self::TAG);
                Ok(end)
            }
            CipherDirection::Decrypt => {
                let message_len = input
                    .len()
                    .checked_sub(Self::TAG.len())
                    .ok_or(TestError::InvalidCiphertext)?;
                for (source, target) in input[..message_len].iter().zip(output.iter_mut()) {
                    *target = *source ^ self.mask;
                }
                // Deliberately validate after writing so the adapter test proves
                // that failed plaintext never reaches its caller's output.
                if input[message_len..] != Self::TAG {
                    return Err(TestError::InvalidCiphertext);
                }
                Ok(message_len)
            }
        }
    }
}

impl IesCipherInit<Params> for TestIesEngine {
    type Error = TestInitError;

    fn init(&mut self, direction: CipherDirection, params: &Params) -> Result<(), Self::Error> {
        self.direction = direction;
        self.mask = params.mask;
        Ok(())
    }
}

#[test]
fn buffers_the_complete_message_until_finalization() {
    let params = Params { mask: 0x5a };
    let mut cipher = BufferedIesCipher::new(TestIesEngine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(cipher.block_size(), 0);
    assert_eq!(cipher.get_update_output_size(100), 0);
    assert_eq!(cipher.process_byte(1, &mut []), Ok(0));
    assert_eq!(cipher.process_bytes(&[2, 3], &mut []), Ok(0));
    assert_eq!(cipher.get_output_size(1), 6);

    let mut encrypted = [0u8; 5];
    assert_eq!(cipher.do_final(&mut encrypted), Ok(5));
    assert_eq!(encrypted, [0x5b, 0x58, 0x59, 0xa5, 0x5a]);

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(cipher.process_bytes(&encrypted, &mut []), Ok(0));
    let mut recovered = [0u8; 3];
    assert_eq!(cipher.do_final(&mut recovered), Ok(3));
    assert_eq!(recovered, [1, 2, 3]);
}

#[test]
fn finalization_errors_clear_the_buffer() {
    let mut cipher = BufferedIesCipher::new(TestIesEngine::new());
    cipher
        .init(CipherDirection::Encrypt, &Params { mask: 0 })
        .unwrap();
    cipher.process_bytes(&[1, 2, 3], &mut []).unwrap();

    assert_eq!(
        cipher.do_final(&mut [0u8; 4]),
        Err(BufferedError::OutputTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(cipher.get_output_size(0), 2);

    cipher
        .init(CipherDirection::Decrypt, &Params { mask: 0 })
        .unwrap();
    cipher.process_bytes(&[1, 2, 3], &mut []).unwrap();
    let mut output = [0xcc];
    assert!(matches!(
        cipher.do_final(&mut output),
        Err(BufferedError::Cipher(TestError::InvalidCiphertext))
    ));
    assert_eq!(output, [0xcc]);
    assert_eq!(cipher.get_output_size(0), 0);
}

#[test]
fn reports_use_before_initialization() {
    let mut cipher = BufferedIesCipher::new(TestIesEngine::new());

    assert!(matches!(
        cipher.process_bytes(&[1], &mut []),
        Err(BufferedError::NotInitialised)
    ));
    assert!(matches!(
        cipher.do_final(&mut []),
        Err(BufferedError::NotInitialised)
    ));
}
