# tc_crypto_engines — porting notes

Developer-facing notes for porting symmetric cipher *engines* from the Bouncy
Castle C# `Org.BouncyCastle.Crypto.Engines` package to Rust. This is a learning
port; for the consumer-facing API, read the rustdoc.

- **Upstream:** bc-csharp, baseline commit `f027bbe1`.
- **Depends on:** [`tc_crypto_core`](../tc_crypto_core) (traits only). Not
  `tc_math` — symmetric engines carry no big-integer arithmetic.
- **Build:** `no_std + alloc` (parameter types own their key bytes). Tests link
  `std` via `#![cfg_attr(not(test), no_std)]`.

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
7. Confirm `cargo test -p tc_crypto_engines`, `cargo clippy --all-targets`, and
   the no_std build (`cargo build -p tc_crypto_engines`).

## Porting status

### Done

| Algorithm | bc engine | Notes |
|-----------|-----------|-------|
| Threefish (Skein 1.3) | `ThreefishEngine` | 256/512/1024-bit tweakable block cipher; KAT-verified |

### Block ciphers — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| TEA / XTEA | `TEAEngine`, `XTEAEngine` | Tiny 64-bit; good next warm-up |
| AES | `AesEngine`, `AesLightEngine`, `RijndaelEngine` | Flagship; table-based + table-free |
| DES / DESede | `DesEngine`, `DesEdeEngine` | |
| Camellia | `CamelliaEngine`, `CamelliaLightEngine` | |
| Serpent | `SerpentEngine`, `TnepresEngine` (`SerpentEngineBase`) | |
| Twofish | `TwofishEngine` | |
| SM4 | `SM4Engine` | |
| Blowfish | `BlowfishEngine` | |
| CAST | `Cast5Engine`, `Cast6Engine` | |
| ARIA | `AriaEngine` | |
| GOST 28147 | `GOST28147Engine` | **Unlocks `tc_digest` GOST 34.11-94** |
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

`AesWrapEngine`, `AesWrapPadEngine`, `AriaWrapEngine`, `AriaWrapPadEngine`,
`CamelliaWrapEngine`, `DesEdeWrapEngine`, `Dstu7624WrapEngine`, `RC2WrapEngine`,
`SEEDWrapEngine`, `RFC3211WrapEngine`, `RFC3394WrapEngine`, `Rfc5649WrapEngine`.
Each wraps an underlying block cipher, so it follows its base engine.

### Asymmetric — TODO (later)

`RsaEngine` / `RSABlindedEngine` / `RSABlindingEngine` / `RSACoreEngine`,
`ElGamalEngine`, `NaccacheSternEngine`, `SM2Engine`, `IesEngine`. These depend on
`tc_math` (big-integer / EC arithmetic) and on asymmetric key-parameter types
(an inheritance hierarchy rooted at `AsymmetricKeyParameter`, owning
`BigInteger`s and sharing domain parameters) — a separate parameter design, owned
and alloc-backed, kept apart from the symmetric parameter types.

> Learning port; no independent security audit. Not a drop-in replacement for an
> audited cryptographic library.
