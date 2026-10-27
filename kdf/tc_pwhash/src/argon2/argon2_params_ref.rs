use super::{Argon2Type, Argon2Version};

/// Borrowed Argon2 parameters, BC's `Argon2Parameters`. Nothing is checked here;
/// [`Argon2::init`](super::Argon2::init) checks them, including what BC's builder checks. The
/// caller owns the bytes and wipes them. There is no `Debug`, so the secret is not printed.
#[derive(Clone, Copy)]
pub struct Argon2ParamsRef<'a> {
    kind: Argon2Type,
    version: Argon2Version,
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
    salt: &'a [u8],
    secret: &'a [u8],
    additional: &'a [u8],
}

impl<'a> Argon2ParamsRef<'a> {
    /// `kind` over `salt`, with BC's defaults: version 0x13, 3 passes, 4096 KiB, 1 lane, and
    /// no secret or associated data. Constant time.
    pub const fn new(kind: Argon2Type, salt: &'a [u8]) -> Self {
        Self {
            kind,
            version: Argon2Version::V13,
            iterations: 3,
            memory_kib: 1 << 12,
            parallelism: 1,
            salt,
            secret: &[],
            additional: &[],
        }
    }

    /// The number of passes, `t`. Constant time.
    pub const fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// The memory in KiB, `m`, as BC's `WithMemoryAsKB`. Constant time.
    pub const fn with_memory_kib(mut self, memory_kib: u32) -> Self {
        self.memory_kib = memory_kib;
        self
    }

    /// The number of lanes, `p`. Constant time.
    pub const fn with_parallelism(mut self, parallelism: u32) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// The version, `v`. Constant time.
    pub const fn with_version(mut self, version: Argon2Version) -> Self {
        self.version = version;
        self
    }

    /// The secret key, `K`. Constant time.
    pub const fn with_secret(mut self, secret: &'a [u8]) -> Self {
        self.secret = secret;
        self
    }

    /// The associated data, `X`. Constant time.
    pub const fn with_additional(mut self, additional: &'a [u8]) -> Self {
        self.additional = additional;
        self
    }

    /// Constant time.
    pub const fn kind(&self) -> Argon2Type {
        self.kind
    }

    /// Constant time.
    pub const fn version(&self) -> Argon2Version {
        self.version
    }

    /// Constant time.
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Constant time.
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Constant time.
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// Constant time: returns the slice without reading it.
    pub const fn salt(&self) -> &'a [u8] {
        self.salt
    }

    /// Constant time: returns the slice without reading it.
    pub const fn secret(&self) -> &'a [u8] {
        self.secret
    }

    /// Constant time: returns the slice without reading it.
    pub const fn additional(&self) -> &'a [u8] {
        self.additional
    }
}
