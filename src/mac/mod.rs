//! [Message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code)
//! implementations and related utilities.

use crate::digest::Digest;

/// A very bad MAC implementation that nobody should use.
///
/// Prefixes the `message` with the provided `key` and hashes it.
#[must_use]
pub fn bad_mac<D: Digest>(key: &[u8], message: &[u8]) -> D::Output {
    <D as Default>::default()
        .chain(key)
        .chain(message)
        .finalize()
}
