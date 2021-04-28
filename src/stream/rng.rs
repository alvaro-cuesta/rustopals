use crate::stream;
use rand::distributions::{DistIter, Standard};
use rand::{Rng, SeedableRng};

pub struct Cipher<R: SeedableRng> {
    rng: R,
}

impl<R: Rng + SeedableRng> stream::Cipher<u8, DistIter<&'static Standard, R, u8>> for Cipher<R> {
    fn keystream(self) -> DistIter<&'static Standard, R, u8> {
        self.rng.sample_iter(&Standard)
    }
}
