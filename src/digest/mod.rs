//! [Message digest](https://en.wikipedia.org/wiki/Message_digest) implementations
//! and utilities.

pub mod md4;
pub mod sha1;

pub use md4::MD4;
pub use sha1::SHA1;

/// Trait for [message digest](https://en.wikipedia.org/wiki/Message_digest) implementations.
pub trait Digest {
    type Output;

    /// Update the digest with `message` bytes
    fn update(&mut self, message: &[u8]);

    /// Finalize the digest and get its value
    fn finalize(self) -> Self::Output;

    /// Convenience method to update the digest with `message` bytes in a
    /// chainable fashion
    fn chain(mut self, message: &[u8]) -> Self
    where
        Self: Sized,
    {
        self.update(message);
        self
    }

    /// Convenience method to update the digest with `message` bytes and
    /// immediately finalize it
    fn digest(mut self, message: &[u8]) -> Self::Output
    where
        Self: Sized,
    {
        self.update(message);
        self.finalize()
    }
}
