//! [Message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code)
//! implementations and utilities.

use crate::digest::Digest;

/// A very bad MAC implementation that nobody should use.
///
/// Prefixes the `message` with the provided `key` and hashes it.
pub fn bad_mac<D>(digest: D, key: &[u8], message: &[u8]) -> D::Output
where
  D: Digest,
{
  let keyed_message = [key, message].concat();

  digest.digest(&keyed_message)
}
