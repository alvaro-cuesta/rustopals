//! [Message-padding schemes](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding)
//! for usage with RSA.

use num_bigint::BigUint;

use crate::digest::Digest;

mod pkcs1v1_5;

pub use pkcs1v1_5::{BadPKCS1v1_5, PKCS1v1_5};

/// Trait implemented by message padding schemes for usage in RSA signatures.
pub trait SignaturePadding {
    /// Hash and pad a `message` for signing.
    fn hash_pad<D>(block_length: usize, message: &[u8]) -> Option<BigUint>
    where
        D: Digest;

    /// Unpad and check hash of `message` against `signature`.
    fn unpad_verify<D>(block_length: usize, message: &[u8], signature: &BigUint) -> bool
    where
        D: Digest;
}

/// **INTENTIONALLY UNSAFE** no-op padding scheme.
pub struct BadNoPadding;

impl SignaturePadding for BadNoPadding {
    fn hash_pad<D>(block_len: usize, message: &[u8]) -> Option<BigUint>
    where
        D: Digest,
    {
        if block_len < D::OUTPUT_LENGTH {
            return None;
        }

        let hash = D::digest(message);
        let biguint = BigUint::from_bytes_be(hash.as_ref());

        Some(biguint)
    }

    fn unpad_verify<D>(block_len: usize, message: &[u8], signature: &BigUint) -> bool
    where
        D: Digest,
    {
        let signature_hash = signature.to_bytes_be();

        if signature_hash.len() > block_len {
            return false;
        }

        let message_hash = D::digest(message);

        signature_hash == message_hash.as_ref()
    }
}
