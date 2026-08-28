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
- **Make illegal states unrepresentable.** Do not ask callers for a variant when
  an authoritative input already selects it (for example, a Threefish key is
  always the same size as its block). Prefer validating in the constructor
  (`ParamType::new(...) -> Result<Self, E>`) so a constructed value is a proof
  of validity, and use a private enum when it helps preserve that proof.
- **`new(...) -> Result` is idiomatic** when construction can fail — do not split
  into `create` / `try_create` (that is a .NET pattern) and do not panic for
  recoverable input. Reserve panics for programmer errors on statically-known
  values.
- **C# inheritance collapses to validated state + match.** Where bc uses an abstract base
  with per-variant subclasses (e.g. `ThreefishCipher` → `Threefish{256,512,1024}
  Cipher`), Rust expresses the closed set as a single routine driven by
  per-variant constant tables selected with `match` — no trait objects, no alloc.

## Crate layout

One module per engine, sibling-style (`foo.rs` + `foo/`):

```
threefish.rs          module root: error type, shared consts, re-exports
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
cargo bench -p tc_crypto_engines --bench aes --locked -- --warm-up-time 1 --measurement-time 2 --sample-size 20

# Force the portable T-table backend by compiling the library without std
cargo bench -p tc_crypto_engines --bench aes --no-default-features --locked -- --warm-up-time 1 --measurement-time 2 --sample-size 20
```

### AES backend performance

The following reference results were measured on 2026-08-27 with an Intel Core
i7-1185G7 and Rust 1.97.1 (`x86_64-pc-windows-msvc`). Each iteration processes
one 16-byte block through the `BlockCipher` API. Engine initialization and key
expansion happen outside the timed loop. Values are Criterion point estimates,
rounded to 0.1 ns; lower is better.

Encryption latency:

| Backend | AES-128 | AES-192 | AES-256 |
|---------|--------:|--------:|--------:|
| AES-NI | 12.8 ns | 14.7 ns | 14.7 ns |
| Portable T-table | 65.4 ns | 77.1 ns | 94.4 ns |
| `AesLightEngine` | 104.5 ns | 125.6 ns | 142.9 ns |

Decryption latency:

| Backend | AES-128 | AES-192 | AES-256 |
|---------|--------:|--------:|--------:|
| AES-NI | 12.0 ns | 11.6 ns | 12.7 ns |
| Portable T-table | 68.3 ns | 81.1 ns | 92.2 ns |
| `AesLightEngine` | 157.9 ns | 187.4 ns | 224.2 ns |

On this machine, the portable T-table backend is about 1.5-1.6x faster than
`AesLightEngine` for encryption and 2.3-2.4x faster for decryption. AES-NI is
about 5.1-6.4x faster than the T-table backend for encryption and 5.7-7.3x
faster for decryption. This gives each implementation a distinct role:

- use AES-NI when hardware support is available;
- use the portable T-table backend when software performance is the priority;
- use `AesLightEngine` when reducing the static table footprint is the priority.

The AES-NI figures come from the default-feature build. The T-table and light
figures come from the same `--no-default-features` run, which forces
`AesEngine` onto its portable backend. Absolute values vary by processor,
compiler, power state, and operating-system scheduling, so performance-sensitive
targets should rerun the benchmark locally.

## Porting status

### Done

| Algorithm | bc engine | Notes |
|-----------|-----------|-------|
| Threefish (Skein 1.3) | `ThreefishEngine` | 256/512/1024-bit tweakable block cipher; KAT-verified |
| Twofish | `TwofishEngine` | 128-bit block and 128/192/256-bit keys; expanded key-dependent S-boxes; BC KAT-verified |
| GOST 28147-89 | `Gost28147Engine` | All bc S-boxes plus validated custom tables; unlocks `tc_digest` GOST 34.11-94 |
| AES | `AesEngine`, `AesLightEngine`, `AesEngine_X86` | AES-128/192/256; 2 KiB portable T-tables, explicit light engine, and runtime-dispatched x86 AES-NI with `std`; BC and FIPS KAT-verified |
| ARIA | `AriaEngine` | ARIA-128/192/256; RFC 5794 KAT-verified |
| Blowfish | `BlowfishEngine` | 32-448-bit keys; legacy 64-bit block cipher; BC KAT-verified |
| Camellia | `CamelliaEngine`, `CamelliaLightEngine` | Camellia-128/192/256; four T-table and 256-byte S-box implementations; RFC/BC KAT-verified |
| CAST | `Cast5Engine`, `Cast6Engine` | CAST-128 (legacy 64-bit block) and CAST-256; shared round functions; RFC 2144/2612 KAT-verified |
| DES / Triple DES | `DesEngine`, `DesEdeEngine` | DES plus two-key and three-key EDE; legacy compatibility only; FIPS/BC KAT-verified |
| DSTU 7624 (Kalyna) | `Dstu7624Engine` | 128/256/512-bit blocks and valid same-size/double-size keys; BC ECB KAT-verified |
| IDEA | `IdeaEngine` | 128-bit key, legacy 64-bit block; shared round function, inverse-key decryption; BC KAT-verified |
| Noekeon | `NoekeonEngine` | 128-bit key/block, direct-key mode; shared theta/pi/gamma layers; BC KAT-verified |
| RC2 | `Rc2Engine` | RFC 2268; variable key with separate effective-key-bits cap, legacy 64-bit block; BC KAT-verified |
| RC5 | `Rc532Engine`, `Rc564Engine` | RFC 2040; one generic core over an `Rc5Word` trait (32-/64-bit words); BC KAT-verified |
| RC6 | `Rc6Engine` | RC6-32/20; RC5-style key schedule plus quadratic mixing; BC/AES-submission KAT-verified |
| Rijndael | `RijndaelEngine` | Generalised (128/160/192/224/256-bit blocks and keys); pre-NIST row form; BC KAT + Monte Carlo verified |
| TEA / XTEA | `TeaEngine`, `XteaEngine` | Tiny 64-bit ciphers, 128-bit key, 32 rounds; XTEA precomputes its round-key schedule; BC KAT-verified |
| SM4 | `Sm4Engine` | GM/T 0002-2012; 128-bit block/key, shared round loop with reversed decryption keys; BC KAT + 1M-iteration verified |
| SEED | `SeedEngine` | RFC 4009; 128-bit block/key, 16-round Feistel with four S-box tables; BC KAT-verified |
| SKIPJACK | `SkipjackEngine` | 80-bit key, legacy 64-bit block; G/H permutations over one F-table; BC KAT-verified |

### Block ciphers — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| Serpent | `SerpentEngine`, `TnepresEngine` (`SerpentEngineBase`) | |

### Stream ciphers — TODO

| Algorithm | bc engine(s) | Notes |
|-----------|--------------|-------|
| RC4 | `RC4Engine` | Planned first implementation; `StreamCipher` core trait is ready |
| Salsa20 / XSalsa20 | `Salsa20Engine`, `XSalsa20Engine` | |
| ChaCha | `ChaChaEngine`, `ChaCha7539Engine`, `XChaCha20Engine` | RFC 7539 + legacy |
| HC-128 / HC-256 | `HC128Engine`, `HC256Engine` | |
| VMPC | `VMPCEngine`, `VMPCKSA3Engine` | |
| ISAAC | `ISAACEngine` | |

The `StreamCipher` trait is now available in `tc_crypto_core`. No stream-cipher
engine has been ported yet; RC4 is the planned first implementation.

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
