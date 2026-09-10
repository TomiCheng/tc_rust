#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
//! Explicit memory erasure with volatile writes and opt-in scope guards.
//!
//! The crate has no dependencies. Its single `alloc` feature is off by default
//! and adds support for `Vec<T>` and `Box<T>`, including boxed slices.
//! [`Zeroize`] supports all primitive integers, `bool`, `char`, arrays, slices,
//! `Option<T>`, and [`core::mem::MaybeUninit<T>`]. [`Zeroizing`] clears a local
//! value when its guard is dropped.
//!
//! # Capability and policy
//!
//! [`Zeroize`] is a capability: a caller can explicitly erase a value. Storage
//! types do not know whether their contents are secret, so implementing this
//! trait should not by itself impose automatic erasure. For example, a big
//! integer used for public arithmetic need not be cleared on drop.
//!
//! [`ZeroizeOnDrop`] expresses a policy chosen by types that know they hold
//! secrets, such as private-key containers. The marker does not generate drop
//! behavior: implementors must provide their own `Drop` implementation and call
//! [`Zeroize::zeroize`]. Use [`Zeroizing`] to opt into this policy for a local value.
//!
//! # Usage
//!
//! ```
//! use tc_zeroize::{Zeroize, Zeroizing};
//!
//! let mut scratch = [1_u8, 2, 3, 4];
//! scratch.zeroize();
//! assert_eq!(scratch, [0; 4]);
//!
//! let mut optional = Some([7_u32, 9]);
//! optional.zeroize();
//! assert_eq!(optional, None);
//!
//! {
//!     let mut secret = Zeroizing::new([42_u8; 32]);
//!     secret[0] = 7;
//!     assert_eq!(secret[0], 7);
//! } // The guard clears its current array before dropping it.
//! ```
//!
//! # Mechanism and limits
//!
//! Primitive implementations overwrite their current storage with volatile
//! writes, followed by a `SeqCst` compiler fence. Volatile stores prevent the
//! compiler from deleting the wipe; the final fence constrains compiler
//! reordering across the wipe. Neither operation flushes caches or supplies a
//! hardware memory barrier. Functional tests check results, not generated code.
//!
//! Arrays and slices visit every element and retain their length; slice lengths
//! are public. `Option<T>` clears a present value before dropping it and becoming
//! `None`. Composite implementations inherit the erasure behavior of their
//! elements. This is not a constant-time API: an option's presence and custom
//! implementations may affect control flow. Padding bytes are not covered.
//! `MaybeUninit<T>` receives a typed volatile zero store and remains logically
//! uninitialized; this does not promise to overwrite padding in `T`. Padding-free
//! storage such as bytes and integer limbs has no such gap.
//!
//! Erasure applies only to the storage reached through the current mutable
//! borrow. It cannot recover copies left elsewhere by the compiler or operating
//! system, including registers, stack spills, swap, and core dumps.
//!
//! A `Copy` value can be implicitly copied on by-value use. Clearing one binding
//! cannot clear other copies; this matters for a `Copy` fixed-width integer type.
//! Such types cannot implement `Drop` and therefore cannot clear themselves
//! automatically at scope exit. Even ordinary moves may leave old bytes behind.
//! A [`Zeroizing`] guard clears its current value, not copies made before or
//! during its lifetime. It cannot prevent copies through [`core::ops::Deref`].
//!
//! With `alloc`, `Vec<T>` clears its live elements before dropping them, then
//! clears the whole current allocation through its spare capacity. Its length
//! becomes zero and capacity is retained. The padding limitation above still
//! applies. `Box<T>` delegates to its contents without releasing the allocation.
//! Collection reallocations can leave data in inaccessible old buffers: erasure
//! cannot reach earlier allocations left by growth, `shrink_to_fit`, or
//! `into_boxed_slice`. Reserve sufficient capacity up front or use `Box<[T]>`
//! for fixed-size secret storage to avoid reallocations while holding secrets.
//! `String` is not supported.
//!
//! Drop-based erasure also requires that the destructor runs: forgetting a guard,
//! leaking it, or aborting the process bypasses its cleanup. If a custom `zeroize`
//! implementation panics, composite erasure can remain incomplete.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod alloc_impls;
mod array;
mod maybe_uninit;
mod option;
mod primitives;
mod slice;
mod traits;
mod zeroizing;

pub use traits::{Zeroize, ZeroizeOnDrop};
pub use zeroizing::Zeroizing;
