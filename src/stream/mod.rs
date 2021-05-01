//! Streaming ciphers and utilities.

use crate::util::iter::Xorable;
use std::iter::{IntoIterator, Map, Zip};
use std::ops::BitXor;

pub mod ctr;
pub mod rng;
pub mod xor;

pub use ctr::CTR;
pub use rng::RNG;
pub use xor::RepeatingXORCipher;
pub use xor::SingleXORCipher;

/// Trait for streaming ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait StreamCipher<K, IK: IntoIterator<Item = K>>
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

/// Trait for seekable streaming ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait SeekableStreamCipher<K, IK: IntoIterator<Item = K>>
where
    Self: Sized,
{
    /// Generates a keystream (an iterator over elements of type `K`) from `offset`.
    fn keystream_from(self, offset: usize) -> IK;

    /// En/decrypts a plain/ciphertext iterator (an iterator over elements of type `T`)
    /// from `offset`.
    fn process_from<T, IT>(
        self,
        offset: usize,
        text: IT,
    ) -> Map<
        Zip<<IT as IntoIterator>::IntoIter, <IK as IntoIterator>::IntoIter>,
        fn((T, K)) -> T::Output,
    >
    where
        T: BitXor<K>,
        IT: IntoIterator<Item = T>,
    {
        text.xor(self.keystream_from(offset))
    }
}
