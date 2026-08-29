//! Serpent and Tnepres vectors from Bouncy Castle's tests.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{SerpentEngine, SerpentParams, TnepresEngine};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn bc_serpent_vectors_encrypt_and_decrypt() {
    let vectors = [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "3620b17ae6a993d09618b8768266bae9",
        ),
        (
            "80000000000000000000000000000000",
            "00000000000000000000000000000000",
            "264e5481eff42a4606abda06c0bfda3d",
        ),
        (
            "d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9",
            "d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9",
            "20ea07f19c8e93fda30f6b822ad5d486",
        ),
        (
            "000000000000000000000000000000000000000000008000",
            "00000000000000000000000000000000",
            "40520018c4ac2bba285aeeb9bcb58755",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000001",
            "ad86de83231c3203a86ae33b721eaa9f",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "3da46ffa6f4d6f30cd258333e5a61369",
            "00112233445566778899aabbccddeeff",
        ),
        (
            "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48",
            "677c8dfaa08071743fd2b415d1b28af2",
            "ea024714ad5c4d84ea024714ad5c4d84",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "4528caccb954d450655e8cfd71cbfac7",
            "00112233445566778899aabbccddeeff",
        ),
        (
            "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300",
            "e0208be278e21420c4b1b9747788a954",
            "ea024714ad5c4d84ea024714ad5c4d84",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "33b3dc87eddd9b0f6a1f407d14919365",
            "00112233445566778899aabbccddeeff",
        ),
        (
            "2bd6459f82c5b300952c49104881ff48",
            "beb6c069393822d3be73ff30525ec43e",
            "ea024714ad5c4d84ea024714ad5c4d84",
        ),
    ];

    for (key_hex, plaintext_hex, ciphertext_hex) in vectors {
        let key = unhex(key_hex);
        let plaintext = unhex(plaintext_hex);
        let ciphertext = unhex(ciphertext_hex);
        let params = SerpentParams::new(&key).unwrap();
        let mut engine = SerpentEngine::new();
        let mut output = [0u8; 16];

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 16);
        assert_eq!(output.as_slice(), ciphertext);

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_block(&ciphertext, &mut output).unwrap();
        assert_eq!(output.as_slice(), plaintext);
    }
}

#[test]
fn bc_tnepres_vectors_encrypt_and_decrypt() {
    let vectors = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "8910494504181950f98dd998a82b6749",
        ),
        (
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "10b5ffb720b8cb9002a1142b0ba2e94a",
        ),
        (
            "00000000000000000000000000000000",
            "00000000008000000000000000000000",
            "4f057a42d8d5bd9746e434680ddcd5e5",
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000400000000000",
            "99407bf8582ef12550886ef5b6f169b9",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "40000000000000000000000000000000",
            "d522a3b8d6d89d4d2a124fdd88f36896",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "00000000000200000000000000000000",
            "189b8ec3470085b3da97e82ca8964e32",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "00000000000000000000008000000000",
            "f77d868cf760b9143a89809510ccb099",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "08000000000000000000000000000000",
            "d43b7b981b829342fce0e3ec6f5f4c82",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000100000000000000",
            "0bf30e1a0c33ccf6d5293177886912a7",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000001",
            "6a7f3b805d2ddcba49b89770ade5e507",
        ),
        (
            "80000000000000000000000000000000",
            "00000000000000000000000000000000",
            "49afbfad9d5a34052cd8ffa5986bd2dd",
        ),
        (
            "000000000000000000000000004000000000000000000000",
            "00000000000000000000000000000000",
            "ba8829b1de058c4b48615d851fc74f17",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000100000000",
            "00000000000000000000000000000000",
            "89f64377bf1e8a46c8247044e8056a98",
        ),
    ];

    for (key_hex, plaintext_hex, ciphertext_hex) in vectors {
        let key = unhex(key_hex);
        let plaintext = unhex(plaintext_hex);
        let ciphertext = unhex(ciphertext_hex);
        let params = SerpentParams::new(&key).unwrap();
        let mut engine = TnepresEngine::new();
        let mut output = [0u8; 16];

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 16);
        assert_eq!(output.as_slice(), ciphertext);

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_block(&ciphertext, &mut output).unwrap();
        assert_eq!(output.as_slice(), plaintext);
    }
}

#[test]
fn bc_serpent_monte_carlo_vectors() {
    let vectors = [
        (
            "f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
            "f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
            "8fd0e58db7a54b929fca6a12f96f20af",
        ),
        (
            "0004000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "e7b681e8871fd05feae5fb64da891ea2",
        ),
        (
            "0000000020000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "c5545d516eec73bfa3622a8194f95620",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000002000000",
            "00000000000000000000000000000000",
            "11ff5c9be006f82c98bd4fac1a19920e",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000010000",
            "47ca1ca404b6481cad4c21c8a0415a0e",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000008000000000000000",
            "a0a2d5b07e27d539ca5bee9de1eab3e6",
        ),
    ];

    for (key_hex, input_hex, expected_hex) in vectors {
        let params = SerpentParams::new(&unhex(key_hex)).unwrap();
        let mut engine = SerpentEngine::new();
        let mut block: [u8; 16] = unhex(input_hex).try_into().unwrap();
        let mut output = [0u8; 16];
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        for _ in 0..100 {
            engine.process_block(&block, &mut output).unwrap();
            block = output;
        }
        assert_eq!(block.as_slice(), unhex(expected_hex));
    }
}

#[test]
fn bc_tnepres_monte_carlo_vectors() {
    let vectors = [
        (
            "47f5f881daab9b67b43bd1342e339c19",
            "7a4f7db38c52a8b711b778a38d203b6b",
            "4db75303d815c2f7cc6ca935d1c5a046",
        ),
        (
            "31fba879ebc5e80df35e6fa33eaf92d6",
            "70a05e12f74589009692a337f53ff614",
            "fc53a50f4d3bc9836001893d2f41742d",
        ),
        (
            "bde6dd392307984695aee80e574f9977caae9aa78eda53e8",
            "9cc523d034a93740a0aa4e2054bb34d8",
            "77117e6a9e80f40b2a36b7d755573c2d",
        ),
        (
            "60f6f8ad4290699dc50921a1bbcca92da914e7d9cf01a9317c79c0af8f2487a1",
            "ee1a61106fae2d381d686cbf854bab65",
            "dcd7f13ea0dcdfd0139d1a42e2ffb84b",
        ),
    ];

    for (key_hex, input_hex, expected_hex) in vectors {
        let params = SerpentParams::new(&unhex(key_hex)).unwrap();
        let mut engine = TnepresEngine::new();
        let mut block: [u8; 16] = unhex(input_hex).try_into().unwrap();
        let mut output = [0u8; 16];
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        for _ in 0..100 {
            engine.process_block(&block, &mut output).unwrap();
            block = output;
        }
        assert_eq!(block.as_slice(), unhex(expected_hex));
    }
}
