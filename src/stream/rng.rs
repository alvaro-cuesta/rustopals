//! RNG-based stream cipher.

use crate::stream;
use rand::distributions::{DistIter, Standard};
use rand::{Rng, SeedableRng};

/// RNG-based stream cipher. The RNG seed is the key.
pub struct Cipher<R: SeedableRng> {
    rng: R,
}

impl<R: SeedableRng> Cipher<R> {
    /// Generate a stream cipher from any seedable RNG. The RNG seed is the key.
    pub fn new(rng: R) -> Cipher<R> {
        Cipher { rng }
    }
}

impl<R: Rng + SeedableRng> stream::Cipher<u8, DistIter<&'static Standard, R, u8>> for Cipher<R> {
    fn keystream(self) -> DistIter<&'static Standard, R, u8> {
        self.rng.sample_iter(&Standard)
    }
}
