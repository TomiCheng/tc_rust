# tc_rsa

Unpadded raw RSA primitives with fixed-width and heap integer backends. The
crate is `no_std` and uses `alloc`. PKCS#1 v1.5, OAEP, PSS, Chaum blind
signatures, and key generation belong to other layers.

## Main types

| Type | Integer representation | CRT | Timing properties | Needs `alloc` |
| --- | --- | :-: | --- | --- |
| `FixedRsaCoreEngine<N>` | `FixedBigUint<N>` | no | fixed-schedule private exponentiation | no for core operations |
| `HeapRsaCoreEngine` | `BigUint` | no | no constant-time guarantee | yes |
| `FixedRsaCrtCoreEngine<N, H>` | `FixedBigUint<N>` / `FixedBigUint<H>` | yes | fixed-schedule private arithmetic | no for raw CRT; yes for blinding inversion |
| `HeapRsaCrtCoreEngine` | `BigUint` | yes | no constant-time guarantee | yes |

The allocation column describes operations, not a feature switch: `tc_rsa`
currently requires `alloc` even when selecting a fixed-width engine. Owned
key containers also allocate. Fixed-width blinding currently uses allocated
scratch space for modular inversion.

The common size aliases are `Rsa1024Core`, `Rsa2048Core`, `Rsa3072Core`,
`Rsa4096Core`, and `Rsa1024CrtCore`, `Rsa2048CrtCore`, `Rsa3072CrtCore`,
`Rsa4096CrtCore`. Custom widths use the re-exported `limbs_for_bits`:

```rust
use tc_rsa::{FixedRsaCoreEngine, FixedRsaCrtCoreEngine, limbs_for_bits};

type Rsa8192Core = FixedRsaCoreEngine<{ limbs_for_bits(8192) }>;
type Rsa8192CrtCore =
    FixedRsaCrtCoreEngine<{ limbs_for_bits(8192) }, { limbs_for_bits(4096) }>;
```

The crate imposes no modulus size limit. Fixed-width capacity is chosen by
the caller's `N`; CRT additionally requires `N == 2 * H` and factors that fit
`H`. Heap widths follow runtime values and available memory. Limb width is
target-dependent, so calculate limb counts rather than hard-coding them.

## Traits and initialization

`Rsa` extends `tc_cipher::AsymmetricBlockCipher`. The parent trait provides
the byte-oriented `process_block` and block sizes; `Rsa` provides
`convert_input` → `process_int` → `convert_output` with a backend-specific
`RsaBigInt` type. `RsaCrt` adds `process_int_blinded`.

`RsaInit<K>` initializes a plain core and `RsaCrtInit<K>` initializes a CRT
core or `RsaBlindedEngine`. Initialization is separate from operations so
operation methods do not carry the key type `K`: callers can invoke them
without ambiguity about which key parameter implementation was used.

## Key parameters

| Key | Borrowed bytes | Owned bytes |
| --- | --- | --- |
| Public or non-CRT private `(n, e)` / `(n, d)` | `RsaKeyRef` | `RsaKeyOwned` |
| CRT private `(n, e, d, p, q, dp, dq, qInv)` | `RsaPrivateCrtKeyRef` | `RsaPrivateCrtKeyOwned` |

All integers use unsigned big-endian bytes. Leading zero bytes are allowed
and an empty slice represents zero. Constructors only store bytes; they do
not validate keys. Each engine's `init` checks basic validity and, for a
fixed-width engine, capacity. These checks are not complete RSA key
validation. Owned containers expose borrowed views through `as_key_ref()`.

## Security notes

Use `RsaBlindedEngine` around a CRT core as the entry point for private-key
operations. Each call samples a fresh blinding factor. Direct CRT core
operations are unblinded unless `process_int_blinded` is explicitly used.
Both CRT cores perform a Lenstra fault check with the public exponent
before returning the CRT result.

Fixed-schedule constant-time properties apply to private arithmetic in
the fixed-width backends. This is not a guarantee for every API operation,
key initialization, or platform. Heap backends explicitly offer no
constant-time guarantee: integer lengths, modular arithmetic, secret CRT
intermediates, and the Lenstra comparison may depend on values.

Fixed scheduling prevents secret exponent bits from changing the operation
schedule. Blinding reduces the observability of remote timing and extra
Montgomery reductions. They address different problems and cannot replace
one another; heap blinding does not establish a fixed schedule.

Owned key containers wipe their byte fields' live contents on drop. They never grow
after construction, so they do not leave new reallocation buffers during their
ownership. Borrowed parameters leave erasure to the caller. Parameter containers
do not implement equality: byte equality is neither constant-time nor numeric
equality under the leading-zero contract.

Heap engines wipe their stored integer fields on drop and before replacing a
successfully reinitialized state. Both CRT backends guard the blinding factor
and its inverse with `Zeroizing`. Fixed-width engines remain `Copy` and do not
automatically wipe their key state; their local guards are best-effort because
copied fixed-width values are outside the guard's protection.

These wipes cover current live storage, not spare capacity, old allocations,
or copies left elsewhere. Other CRT and blinding intermediates remain unwiped.
Cleanup requires destructors to run and does not flush caches or supply a
hardware memory barrier.

## Example

This executable example is also the crate-level doc test. It uses a public
Wycheproof RSA-2048 test key and a deterministic demonstration RNG; neither
is suitable for production. Real applications must supply their own keys,
a cryptographic RNG, and a suitable encoding/padding layer.

```rust
use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
use tc_rsa::{
    Rsa2048Core, Rsa2048CrtCore, RsaBlindedEngine, RsaCrtInit, RsaError,
    RsaInit, RsaKeyRef, RsaPrivateCrtKeyRef,
};

fn main() -> Result<(), RsaError> {
    // 公開測試金鑰僅供範例；實際用途必須使用自己的金鑰與密碼學 RNG。
    let values = key_2048();
    let public_key = RsaKeyRef::new(false, &values[0], &values[1]);
    let private_key = RsaPrivateCrtKeyRef::new(
        &values[0], &values[1], &values[2], &values[3],
        &values[4], &values[5], &values[6], &values[7],
    );
    let mut public = Rsa2048Core::default();
    public.init(CipherDirection::Encrypt, &public_key)?;
    let mut private: RsaBlindedEngine<Rsa2048CrtCore, _> =
        RsaBlindedEngine::new(ExampleRng(1));
    private.init(CipherDirection::Decrypt, &private_key)?;

    let message = [42_u8];
    // 原始 RSA 的緩衝區保留完整模數寬度。
    let mut ciphertext = [0_u8; 256];
    let cipher_len = public.process_block(&message, &mut ciphertext)?;
    let mut recovered = [0_u8; 256];
    let len = private.process_block(&ciphertext[..cipher_len], &mut recovered)?;
    assert_eq!(&recovered[..len], &message);
    Ok(())
}

// 決定性 RNG 僅供範例與效能比較，不能用於正式的私鑰運算。
struct ExampleRng(u64);

impl rand_core::TryRng for ExampleRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ExampleRng {}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn key_2048() -> [Vec<u8>; 8] {
    // C2SP Wycheproof rsa_pkcs1_2048_test.json 第一組金鑰的 JWK 參數。
    // https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_2048_test.json
    [
        hex_bytes(
            "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
        ),
        hex_bytes("010001"),
        hex_bytes(
            "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
        ),
        hex_bytes(
            "ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b",
        ),
        hex_bytes(
            "c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987",
        ),
        hex_bytes(
            "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5",
        ),
        hex_bytes(
            "0554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f",
        ),
        hex_bytes(
            "1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559",
        ),
    ]
}
```
