//! Streaming ciphers and utilities.

use crate::util::iter::Xorable;
use std::iter::{IntoIterator, Map, Zip};
use std::ops::BitXor;

pub mod ctr;
pub mod rng;
pub mod xor;

/// Trait for streaming ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait Cipher<K, IK: IntoIterator<Item = K>>
where
    Self: Sized,
{
    /// Generates a keystream (an iterator over elements of type `K`).
    fn keystream(self) -> IK;

    /// En/decrypts a plain/ciphertext iterator (an iterator over elements of type `T`).
    fn process<T, IT>(
        self,
        text: IT,
    ) -> Map<
        Zip<<IT as IntoIterator>::IntoIter, <IK as IntoIterator>::IntoIter>,
        fn((T, K)) -> T::Output,
    >
    where
        T: BitXor<K>,
        IT: IntoIterator<Item = T>,
    {
        text.xor(self.keystream())
    }
}
