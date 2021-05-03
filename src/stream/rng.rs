//! [RNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)-based stream cipher.

use rand::distributions::{DistIter, Standard};
use rand::{Rng, SeedableRng};

use crate::stream::StreamCipher;

/// [RNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)-based stream cipher.
/// The RNG seed is the key.
pub struct RNG<R: SeedableRng> {
    rng: R,
}

impl<R: SeedableRng> RNG<R> {
    /// Generate a stream cipher from any seedable RNG. The RNG seed is the key.
    pub fn new(rng: R) -> RNG<R> {
        RNG { rng }
    }
}

impl<R: Rng + SeedableRng> StreamCipher<u8, DistIter<&'static Standard, R, u8>> for RNG<R> {
    fn keystream(self) -> DistIter<&'static Standard, R, u8> {
        self.rng.sample_iter(&Standard)
    }
}
