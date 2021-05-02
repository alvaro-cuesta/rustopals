//! [Message digest](https://en.wikipedia.org/wiki/Message_digest) implementations
//! and related utilities.

pub mod md4;
pub mod sha1;

pub use md4::MD4;
pub use sha1::SHA1;

/// Trait for [message digest](https://en.wikipedia.org/wiki/Message_digest) implementations.
pub trait Digest {
    type Output: AsRef<[u8]>;

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

/// Trait for digests that can be subject to
/// [length-extension attacks](https://en.wikipedia.org/wiki/Length_extension_attack).
///
/// Useful for cracking bad MAC constructs like naive key-prefixed MACs.
pub trait ExtensibleDigest: Digest + Sized {
    /// Perform a length-extension attack on an existing digest result.
    ///
    /// Given:
    ///
    /// - `digest_output`: A known digest that we want to extend.
    /// - `guessed_payload_length`: The guessed length of what has been
    ///   digested so far (not including the padding).
    ///
    /// It returns:
    ///
    /// - The reverse-engineered `Digest` that we can extend.
    /// - The synthetic padding as a `Vec<u8>` that we have to append to our
    ///   plaintext before extending it.
    fn extend_digest(
        digest_output: <Self as Digest>::Output,
        guessed_payload_length: usize,
    ) -> (Self, Vec<u8>);
}
