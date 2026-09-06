# Shared elliptic-curve algorithms

The API remains draft. This crate owns generic algorithms; concrete field and
coordinate formulas stay in the Fp/F2m backends. `tc_constant_time` supplies small
selection primitives shared with `tc_bigint`, keeping the dependency graph acyclic.

## Public inputs

`sum_of_two_multiplies` and `sum_of_multiplies` interleave wNAF streams in one
doubling loop. `shamirs_trick` uses joint sparse form. All accept unsigned
`Curve::Scalar`; represent a negative coefficient by negating its point.
`generate_jsf` carries separately so full-width integers never overflow.

`import_point` transfers affine coordinates between equivalent field/equation
domains, including different coordinate systems. `clean_point` additionally
validates the rebuilt point against the destination subgroup. `validate_point`
accepts identity, as a group operation should; protocols must apply their own
nonidentity rules. Multi-scalar functions validate inputs and results.

`montgomery_trick` inverts a nonempty batch with one inversion; optional scaling
matches BC's `1/(value*scale)` contract. Zero causes an error without mutation.
An empty batch is a no-op. `normalize_all` skips affine, identity and unit-Z
points and supplies the resulting inverses through `Point::normalize_with_inverse`.
wNAF precomputation uses that batch path.

`FixedPointTable` is a caller-owned, variable-time comb with explicit scalar
capacity; oversized inputs are rejected rather than truncated. `PointMap` and
`GlvEndomorphism` replace BC's interface/inheritance hierarchy. `ScalePointMap`
can express scaling either coordinate and negating the other by choosing its
two field multipliers. `tc_fp_custom::SecP256K1Glv` implements the Type B lattice
decomposition from BC. The caller opts into GLV using `glv_mul`.

## Secret inputs

`multiply_secret` and `sum_of_two_multiplies_secret` take **public validated
points** and secret little-endian scalar byte slices. Slice lengths are public.
Every bit, including leading zeros, is processed; callers should consistently
use their protocol's fixed width. There is no implicit clamping or reduction.

`SecretPoint` stores projective coordinates without `Option`-based identity.
Fp uses Jacobian formulas and F2m uses homogeneous formulas. Equal, opposite,
identity and torsion cases are evaluated and selected with masks. The window
width is four, and `ECLookupTable` scans every entry. Out-of-range lookup returns
identity. No abstract lookup-table superclass is needed in Rust.

The result stays a `SecretPoint`; `reveal()` explicitly declassifies it before
constructing an ordinary point. Ordinary normalization, point validation and
encoding are not implicitly claimed to be secret-safe.

Backends implement `SecretField` separately from ordinary arithmetic:

- Fixed-width generic Fp uses Montgomery residues. Reduction/add/subtract and
  selection in `tc_bigint` use full limb scans; `pow_ct` processes every bit.
- Specialized Fp/SM2 uses a portable fixed-schedule modular kernel. The existing
  faster Solinas code remains for public operands because it has varying carry loops.
- F2m uses fixed-degree carryless arithmetic and exponentiation. Storage must
  implement `SecretPolynomial`, whose reconstruction/clone size is public.
- Dynamic `BigUint` Fp is excluded because normalized lengths depend on values.

These are source-level data-independent schedules, not a claim of a completed
platform timing audit. `Choice` obscures masks from optimization with `black_box`;
Rust does not formally guarantee constant-time machine code. Review generated
code on deployment targets. Tests establish functional equivalence, not timing.

## Deliberate omissions

BC's `field/` descriptor interfaces serve runtime/ASN.1 metadata. The arithmetic
contracts are represented by Rust associated types, so those interfaces and
`IsFpCurve`/`IsF2mCurve` are not ported. Fixed-width const-generic integers replace
`Nat128..Nat576`. AES GF(256) belongs in crypto, outside this math layer.

## Validation

`tc_fp_custom/tests/algorithms.rs` covers JSF full-width reconstruction, public
multi-scalar equivalence, batch error behavior, comb, GLV and secret edge cases.
`all_named_secret.rs` covers all 13 specialized prime curves (including SM2) and
18 specialized binary curves: scalar multiples, subgroup order, zero inversion,
field inverse identities and batch normalization. Generic fixed-width Fp is
also compared against its public implementation.

Run `cargo test -p tc_fp_custom --release --locked`, followed by affected crate
tests, no-default builds, Clippy and rustdoc. Release mode is useful for the
portable secret-field kernels; debug mode checks overflow invariants as well.
