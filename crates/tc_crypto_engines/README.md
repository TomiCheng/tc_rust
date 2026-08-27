# tc_crypto_engines — porting notes

Developer-facing notes for porting symmetric cipher *engines* from the Bouncy
Castle C# `Org.BouncyCastle.Crypto.Engines` package to Rust. This is a learning
port; for the consumer-facing API, read the rustdoc.

- **Upstream:** bc-csharp, baseline commit `f027bbe1`.
- **Depends on:** [`tc_crypto_core`](../tc_crypto_core) (traits only). Not
  `tc_math` — symmetric engines carry no big-integer arithmetic.
- **Build:** the default `std` feature enables runtime CPU-feature detection;
  `--no-default-features` builds as `no_std + alloc` and uses portable backends.
  Parameter types own their key bytes.

## Design conventions

Decisions made while bringing up the first engine; apply them to the next ones.

- **`tc_crypto_core` is traits only.** The `BlockCipher` trait ships the contract;
  every concrete parameter/key/error type lives here in the engine crate, not in
  core. This is the `rand_core` model (core defines `SeedableRng`, implementors
  supply `Seed`).
- **Parameters are associated types, not a shared `KeyParameter`.** A single
  `KeyParameter` cannot express per-algorithm key-length rules, so each engine
  names its own `type Params<'a>`. A generic associated type + `init(&mut self,
  bool, &Self::Params<'_>)` (by reference) lets a param either borrow (`&'a [u8]`)
  or own (lifetime-free), and lets one expensive, shared parameter value drive
  many `init` calls without being consumed.
- **Key-bearing parameters are not `Clone` and must redact `Debug`.** Passing
  parameters to `init` by reference permits deliberate reuse without creating
  additional copies of key material. A custom `Debug` implementation may expose
  structural metadata such as key length or whether an optional tweak is
  present, but never key, tweak, nonce, or other sensitive bytes.
- **Errors are an associated type** (`type Error: core::error::Error`). No shared
  error enum in core; each engine defines its own.
- **No fallible/infallible split** for `BlockCipher` (unlike `TryDigest` /
  `Digest`): a block cipher's `init` validates its key and can genuinely fail, so
  there is no useful infallible variant.
- **Make illegal states unrepresentable.** Prefer an enum over a raw size where
  the valid set is closed (e.g. `ThreefishBlockSize` — an unsupported block size
  cannot be named, so the constructor is infallible). Prefer validating in the
  constructor (`ParamType::new(...) -> Result<Self, E>`) so a constructed value
  is a proof of validity, and validate each field at the stage that has the
  context (a variant-independent length in the param constructor; a
  variant-dependent one at `init`).
- **`new(...) -> Result` is idiomatic** when construction can fail — do not split
  into `create` / `try_create` (that is a .NET pattern) and do not panic for
  recoverable input. Reserve panics for programmer errors on statically-known
  values.
- **C# inheritance collapses to enum + match.** Where bc uses an abstract base
  with per-variant subclasses (e.g. `ThreefishCipher` → `Threefish{256,512,1024}
  Cipher`), Rust expresses the closed set as a single routine driven by
  per-variant constant tables selected with `match` — no trait objects, no alloc.

## Crate layout

One module per engine, sibling-style (`foo.rs` + `foo/`):

```
threefish.rs          module root: public enums, error type, shared consts, re-exports
threefish/params.rs   validated, owned init parameters (ParamType::new -> Result)
threefish/engine.rs   the engine struct + `impl BlockCipher`
threefish/cipher.rs   private round functions / per-variant tables
tests/threefish_kat.rs  known-answer tests against upstream vectors
```

## Adding an engine

1. Create `<name>.rs` + `<name>/` and register it in `lib.rs`.
2. Define the error enum (`impl core::error::Error`) and any block-size / mode
   enum in the module root.
3. Define the parameter type in `<name>/params.rs` with a validating
   `new(...) -> Result<Self, Error>`.
4. Implement the engine in `<name>/engine.rs`: `impl BlockCipher` with
   `type Params<'a>` and `type Error`. Put dense round code in `<name>/cipher.rs`.
5. Prefer the spec form (constant tables + `match`) over transcribing bc's
   unrolled/SIMD loops; the output must still match bit-for-bit.
6. Add KAT tests in `tests/<name>_kat.rs`. Pull vectors from bc's own test data
   (`crypto/test/src/crypto/test/<Name>Test.cs`) so there is no transcription
   drift, and cover both encrypt and decrypt.
7. Confirm `cargo test -p tc_crypto_engines --locked`, strict Clippy
   (`cargo clippy -p tc_crypto_engines --all-targets --locked -- -D warnings`),
   and the no_std build
   (`cargo build -p tc_crypto_engines --no-default-features --locked`).

## Benchmarks

AES single-block encryption and decryption benchmarks cover all three key sizes
and compare the runtime-dispatched `AesEngine` with the always-portable
`AesLightEngine`:

```console
# Runtime-dispatched backend (AES-NI on supported x86/x86_64 CPUs)
cargo bench -p tc_crypto_engines --bench aes

# Force the portable backend by compiling the library without std
cargo bench -p tc_crypto_engines --bench aes --no-default-features
```

## Porting status

### Done

| Algorithm | bc engine | Notes |
|-----------|-----------|-------|
| Threefish (Skein 1.3) | `ThreefishEngine` | 256/512/1024-bit tweakable block cipher; KAT-verified |
| GOST 28147-89 | `Gost28147Engine` | All bc S-boxes plus validated custom tables; unlocks `tc_digest` GOST 34.11-94 |
| AES | `AesEngine`, `AesLightEngine`, `AesEngine_X86` | AES-128/192/256; explicit light/portable engine plus runtime-dispatched x86 AES-NI with `std`; BC and FIPS KAT-verified |

### Block ciphers — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| TEA / XTEA | `TEAEngine`, `XTEAEngine` | Tiny 64-bit; good next warm-up |
| Rijndael | `RijndaelEngine` | Generalized Rijndael block sizes; AES is implemented separately above |
| DES / DESede | `DesEngine`, `DesEdeEngine` | |
| Camellia | `CamelliaEngine`, `CamelliaLightEngine` | |
| Serpent | `SerpentEngine`, `TnepresEngine` (`SerpentEngineBase`) | |
| Twofish | `TwofishEngine` | |
| SM4 | `SM4Engine` | |
| Blowfish | `BlowfishEngine` | |
| CAST | `Cast5Engine`, `Cast6Engine` | |
| ARIA | `AriaEngine` | |
| SEED | `SEEDEngine` | |
| RC2 / RC5 / RC6 | `RC2Engine`, `RC532Engine`, `RC564Engine`, `RC6Engine` | |
| IDEA | `IdeaEngine` | |
| Noekeon | `NoekeonEngine` | |
| Skipjack | `SkipjackEngine` | |
| DSTU 7624 | `Dstu7624Engine` | |

### Stream ciphers — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| RC4 | `RC4Engine` | Simplest; first `StreamCipher` |
| Salsa20 / XSalsa20 | `Salsa20Engine`, `XSalsa20Engine` | |
| ChaCha | `ChaChaEngine`, `ChaCha7539Engine`, `XChaCha20Engine` | RFC 7539 + legacy |
| HC-128 / HC-256 | `HC128Engine`, `HC256Engine` | |
| VMPC | `VMPCEngine`, `VMPCKSA3Engine` | |
| ISAAC | `ISAACEngine` | |

Needs a `StreamCipher` trait in `tc_crypto_core` first.

### AEAD engines — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| Ascon | `AsconEngine` | |
| Sparkle (SCHWAEMM) | `SparkleEngine` | Shares the SPARKLE permutation with ESCH → **unlocks `tc_digest` ESCH-256/384** |
| Grain-128 AEAD | `Grain128AEADEngine` | |

Needs an `AeadCipher` trait in `tc_crypto_core` first (key + nonce + mac size +
optional AAD; `init` takes those four).

### Key wrap — TODO

Key-wrap implementations sit above the primitive engines and should eventually
live in a higher-level crate (for example, `tc_key_wrap`). That crate may depend
on both `tc_crypto_engines` and `tc_digest`; putting these wrappers here would
make it easy to create a `tc_digest` <-> `tc_crypto_engines` dependency cycle.

| Wrapper(s) | Dependencies / prerequisite |
|------------|-----------------------------|
| `RFC3394WrapEngine`, `Rfc5649WrapEngine` | A caller-supplied block cipher; RFC 5649 also reuses RFC 3394 |
| `AesWrapEngine`, `AesWrapPadEngine` | `AesEngine` plus RFC 3394 / RFC 5649 |
| `AriaWrapEngine`, `AriaWrapPadEngine` | `AriaEngine` plus RFC 3394 / RFC 5649 |
| `CamelliaWrapEngine`, `SEEDWrapEngine` | Their base engine plus RFC 3394 |
| `Dstu7624WrapEngine` | `Dstu7624Engine` |
| `RFC3211WrapEngine` | A caller-supplied block cipher, CBC mode, and a secure random source for wrapping |
| `DesEdeWrapEngine` | `DesEdeEngine`, CBC mode, and **SHA-1 from `tc_digest`** for the fixed CMS checksum |
| `RC2WrapEngine` | `RC2Engine`, CBC mode, and **SHA-1 from `tc_digest`** for the fixed RFC 3217 CMS checksum |

SHA-1 is part of the `DesEdeWrapEngine` and `RC2WrapEngine` formats, not a
replaceable digest choice. These two wrappers must therefore remain above both
the engine and digest crates.

### Asymmetric — TODO (later)

`RsaEngine` / `RSABlindedEngine` / `RSABlindingEngine` / `RSACoreEngine`,
`ElGamalEngine`, `NaccacheSternEngine`, `SM2Engine`, `IesEngine`. These depend on
`tc_math` (big-integer / EC arithmetic) and on asymmetric key-parameter types
(an inheritance hierarchy rooted at `AsymmetricKeyParameter`, owning
`BigInteger`s and sharing domain parameters) — a separate parameter design, owned
and alloc-backed, kept apart from the symmetric parameter types.

> Learning port; no independent security audit. Not a drop-in replacement for an
> audited cryptographic library.
