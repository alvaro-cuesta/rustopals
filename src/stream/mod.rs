//! [Stream ciphers](https://en.wikipedia.org/wiki/Stream_cipher) and related utilities.

use std::iter::{IntoIterator, Map, Zip};
use std::ops::BitXor;

use crate::util::iter::Xorable;

pub mod ctr;
pub mod rng;
pub mod xor;

pub use ctr::CTR;
pub use rng::RNG;
pub use xor::{RepeatingXORCipher, SingleXORCipher};

/// Trait for stream ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait StreamCipher<K, IK: IntoIterator<Item = K>>
where
    Self: Sized,
{
    /// Generates a keystream (an iterator over elements of type `K`).
    fn keystream(self) -> IK;

    /// En/decrypts a plain/ciphertext iterator (an iterator over elements of type `T`).
    #[allow(clippy::type_complexity)]
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

/// Trait for seekable stream ciphers, which allow seeking into any position of the stream.
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
    #[allow(clippy::type_complexity)]
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
