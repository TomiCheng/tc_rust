# tc_aes

AES-128, AES-192 and AES-256 block ciphers with AES-NI, RustCrypto,
table-based and small-footprint engines.

## Single-block benchmark results

Measured on 2026-09-23 on the local Windows x86-64 host with AES-NI available,
using Rust 1.98.0 and Cargo's optimized bench profile. The CPU model was not
recorded. These results describe this host and run, not a cross-platform ranking.

Each of the 24 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's central time
estimates, rounded to one decimal place.

**Nanoseconds per 16-byte block; lower is better. Each cell is encryption /
decryption.**

| Engine | AES-128 | AES-192 | AES-256 |
| --- | ---: | ---: | ---: |
| `AesX86Engine` (AES-NI) | 12.1 / 10.2 | 12.0 / 10.4 | 13.4 / 11.6 |
| `AesRustCryptoEngine` | 14.2 / 11.6 | 14.4 / 12.4 | 15.0 / 13.4 |
| `AesTableEngine` | 70.5 / 77.3 | 81.1 / 87.8 | 91.5 / 101.3 |
| `AesLightEngine` | 118.0 / 147.3 | 140.6 / 173.9 | 161.8 / 207.9 |

AES-NI was fastest in this run, followed by RustCrypto, Table and Light.
The measurements include each engine's `process_block` API overhead but exclude
key setup, construction and final drop. They call the four engines directly,
not the `AesEngine` dispatcher. Decryption uses ciphertext prepared before timing.

These are single-block measurements, not multi-block parallel throughput or
constant-time verification. Some samples were outliers; system load and CPU
behaviour can affect small differences. The RustCrypto engine chooses its own
backend; this benchmark does not report that internal selection.

### Security and engine selection

- `AesX86Engine` uses AES-NI with a constant-time key schedule and requires
  runtime support.
- `AesRustCryptoEngine` provides hardware acceleration with a constant-time
  software fallback on supported platforms.
- `AesTableEngine` and `AesLightEngine` use secret-dependent table lookups and
  are variable time. Light trades smaller lookup tables for lower speed here.
- `AesEngine` chooses RustCrypto when the `rustcrypto` feature is enabled.
  Otherwise it chooses AES-NI when available,
  falling back to Table. Its default configuration therefore does not guarantee
  constant-time processing on every host.

## Running the benchmarks

Reproduce the four-engine single-block comparison:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked -- '^aes/(encrypt|decrypt)/(table|light|aes-ni|rustcrypto)/'
```

Run all benchmarks, including dispatcher and key setup measurements:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked
```

Setup benchmarks reinitialise an existing engine, including replacement of its
previous key schedule. They exclude construction and final drop. AES-NI cases
are skipped when unavailable; RustCrypto cases require the `rustcrypto` feature.
The full suite takes roughly 18 minutes on a host running all 60 cases, plus
compilation and analysis time.

For a smoke test without performance measurement:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked -- --test
```
