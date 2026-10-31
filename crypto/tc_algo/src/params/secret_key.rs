use core::fmt;

use tc_zeroize::Zeroize;

// The bytes of a symmetric key, for AES and every other algorithm that takes one. There is no
// type per algorithm: the factory entry already names it, and to each of them a key is bytes.
// Nothing checks the length here; the algorithm does when it is initialized
#[non_exhaustive]
pub struct SecretKey {
    pub key: Vec<u8>,
}

impl SecretKey {
    // Takes the vector over without copying it
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

// Each copy is wiped on drop in its turn
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self::new(self.key.clone())
    }
}

// Wipes the bytes this holds; copies made elsewhere, such as the buffers a growing Vec left
// behind, are not reached
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// Shows the length, never the bytes
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &self.key.len())
            .finish_non_exhaustive()
    }
}
