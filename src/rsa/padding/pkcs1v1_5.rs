//! [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313) padding.

use num_bigint::BigUint;

use crate::digest::Digest;
use crate::rsa::SignaturePadding;

/// **INTENTIONALLY UNSAFE** [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313)
/// padding implementation that stops parsing the block after the hash, even if
/// there are bytes remaining.
///
/// This was made intentionally bad to [Cryptopals challenge 42](https://cryptopals.com/sets/6/challenges/42)
pub struct BadPKCS1v1_5;

impl SignaturePadding for BadPKCS1v1_5 {
    fn hash_pad<D>(block_len: usize, message: &[u8]) -> Option<BigUint>
    where
        D: Digest,
    {
        PKCS1v1_5::hash_pad::<D>(block_len, message)
    }

    fn unpad_verify<D>(block_len: usize, message: &[u8], signature: &BigUint) -> bool
    where
        D: Digest,
    {
        let block = signature.to_bytes_be();

        if block.len() != block_len - 1 || block[0] != 0x01 {
            return false;
        }

        let mut padding_end = 1;

        while padding_end < block.len() && block[padding_end] == 0xff {
            padding_end += 1;
        }

        if padding_end == 1 || block[padding_end] != 0 {
            return false;
        }

        padding_end += 1;

        let asn1_prefix_len = D::ASN1_PREFIX.len();
        let asn1_prefix = &block[padding_end..padding_end + asn1_prefix_len];

        if asn1_prefix != D::ASN1_PREFIX {
            return false;
        }

        let hash_len = D::OUTPUT_LENGTH;
        let signature_hash =
            &block[padding_end + asn1_prefix_len..padding_end + asn1_prefix_len + hash_len];
        let message_hash = D::digest(message);

        signature_hash == message_hash.as_ref()
    }
}

/// [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313) padding implementation.
pub struct PKCS1v1_5;

impl SignaturePadding for PKCS1v1_5 {
    fn hash_pad<D>(block_len: usize, message: &[u8]) -> Option<BigUint>
    where
        D: Digest,
    {
        let hash = D::digest(message);
        let hash_len = hash.as_ref().len();
        let prefix_len = D::ASN1_PREFIX.len();

        if block_len < hash_len + prefix_len + 11 {
            return None;
        }

        let mut block = vec![0xff; block_len];

        block[0] = 0x00;
        block[1] = 0x01;
        block[block_len - hash_len - prefix_len - 1] = 0x00;
        block[block_len - hash_len - prefix_len..block_len - hash_len]
            .copy_from_slice(D::ASN1_PREFIX);
        block[block_len - hash_len..].copy_from_slice(hash.as_ref());

        Some(BigUint::from_bytes_be(&block))
    }

    #[allow(clippy::shadow_unrelated)]
    fn unpad_verify<D>(block_len: usize, message: &[u8], signature: &BigUint) -> bool
    where
        D: Digest,
    {
        let block = signature.to_bytes_be();

        // - 1 because first 0x00 is dropped on `to_bytes_be`
        if block.len() != block_len - 1 || block[0] != 0x01 {
            return false;
        }

        let hash_len = D::OUTPUT_LENGTH;
        let prefix_len = D::ASN1_PREFIX.len();
        let block_len = block.len();

        if block[block_len - hash_len - prefix_len - 1] != 0x00 {
            return false;
        }

        let padding_len = block_len - hash_len - prefix_len - 2;
        if padding_len < 8 {
            return false;
        }

        let is_valid_padding = block[1..1 + padding_len].iter().all(|&x| x == 0xff);

        if !is_valid_padding {
            return false;
        }

        let asn1_prefix = &block[block_len - hash_len - prefix_len..block_len - hash_len];

        if asn1_prefix != D::ASN1_PREFIX {
            return false;
        }

        let signature_hash = &block[block_len - hash_len..];
        let message_hash = D::digest(message);

        signature_hash == message_hash.as_ref()
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigUint;

    use super::{BadPKCS1v1_5, PKCS1v1_5, SignaturePadding};
    use crate::digest::{Digest, SHA256};

    const BITS: usize = 1024;

    #[test]
    fn test_pkcs1_v1_5_signature_pad() {
        let padded_message = PKCS1v1_5::hash_pad::<SHA256>(BITS / 8, &[]).unwrap();

        // + 15 because of 0x0001 left-side padding = 15 zero bits
        assert_eq!(padded_message.bits() + 15, BITS as u64);

        assert_eq!(
            padded_message.to_bytes_be(),
            [
                &[0x01_u8] as &[u8],
                &[0xff; 74],
                &[0x00],
                <SHA256 as Digest>::ASN1_PREFIX,
                &SHA256::digest(&[]),
            ]
            .concat()
        );
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_start() {
        let signature_bytes = [
            &[0x13_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_len() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 37],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_padding() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0x13; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_before_prefix() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x13],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_prefix() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            &[0x00; <SHA256 as Digest>::ASN1_PREFIX.len()],
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_bad_digest() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(b"Not empty slice!"),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = PKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_reject_short_padding() {
        let prefix = <SHA256 as Digest>::ASN1_PREFIX;
        let digest = SHA256::digest(&[]);

        let signature_bytes = [&[0x01_u8] as &[u8], &[0xff; 7], &[0x00], prefix, &digest].concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid =
            PKCS1v1_5::unpad_verify::<SHA256>(10 + prefix.len() + digest.len(), &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_pkcs1_v1_5_signature_unpad_min_padding() {
        let prefix = <SHA256 as Digest>::ASN1_PREFIX;
        let digest = SHA256::digest(&[]);

        let signature_bytes = [&[0x01_u8] as &[u8], &[0xff; 8], &[0x00], prefix, &digest].concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid =
            PKCS1v1_5::unpad_verify::<SHA256>(11 + prefix.len() + digest.len(), &[], &signature);

        assert!(is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_pad() {
        let padded_message = BadPKCS1v1_5::hash_pad::<SHA256>(BITS / 8, &[]).unwrap();

        // + 15 because of 0x0001 left-side padding = 15 zero bits
        assert_eq!(padded_message.bits() + 15, BITS as u64);

        assert_eq!(
            padded_message.to_bytes_be(),
            [
                &[0x01_u8] as &[u8],
                &[0xff; 74],
                &[0x00],
                <SHA256 as Digest>::ASN1_PREFIX,
                &SHA256::digest(&[]),
            ]
            .concat()
        );
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_start() {
        let signature_bytes = [
            &[0x13_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_len() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 37],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_padding() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0x13; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_before_prefix() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x13],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_prefix() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            &[0x00; <SHA256 as Digest>::ASN1_PREFIX.len()],
            &SHA256::digest(&[]),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_reject_bad_digest() {
        let signature_bytes = [
            &[0x01_u8] as &[u8],
            &[0xff; 74],
            &[0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(b"Not empty slice!"),
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_bad_pkcs1_v1_5_signature_unpad_accepts_right_garbage() {
        let signature_bytes = [
            &[0x01, 0xff, 0x00],
            <SHA256 as Digest>::ASN1_PREFIX,
            &SHA256::digest(&[]),
            &[0x13; 73],
        ]
        .concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid = BadPKCS1v1_5::unpad_verify::<SHA256>(BITS / 8, &[], &signature);

        assert!(is_valid);
    }
}
