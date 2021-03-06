//! [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313) padding.

use std::iter;

use num_bigint::BigUint;
use rand::distributions::Standard;
use rand::{thread_rng, Rng};

use crate::digest::Digest;
use crate::rsa::{EncrytionPadding, SignaturePadding};

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

        if block.len() + 1 != block_len || block[0] != 0x01 {
            return false;
        }

        let mut padding_end = 1;

        while padding_end < block.len() && block[padding_end] == 0xff {
            padding_end += 1;
        }

        if padding_end == 1 || block[padding_end] != 0x00 {
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
        if block.len() + 1 != block_len || block[0] != 0x01 {
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

        #[allow(clippy::range_plus_one)]
        let is_valid_padding = block[1..1 + padding_len].iter().all(|&x| x == 0xff);

        if !is_valid_padding {
            return false;
        }

        if block[padding_len + 1] != 0x00 {
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

impl EncrytionPadding for PKCS1v1_5 {
    fn pad(block_len: usize, plaintext: &[u8]) -> Option<BigUint> {
        if block_len < plaintext.len() + 11 {
            return None;
        }

        let padding_len = block_len - 3 - plaintext.len();
        let padding_bytes_iter = thread_rng()
            .sample_iter::<u8, _>(Standard)
            .filter(|&x| x > 0)
            .take(padding_len);

        let bytes = iter::once(0x02_u8)
            .chain(padding_bytes_iter)
            .chain(iter::once(0x00_u8))
            .chain(plaintext.iter().copied())
            .collect::<Vec<_>>();

        assert_eq!(bytes.len(), block_len - 1);

        Some(BigUint::from_bytes_be(&bytes))
    }

    fn unpad(block_len: usize, ciphertext: &BigUint) -> Option<Vec<u8>> {
        let bytes = ciphertext.to_bytes_be();

        if bytes.len() + 1 != block_len || bytes[0] != 0x02 {
            return None;
        }

        let padding_len = bytes[1..].iter().position(|&x| x == 0)?;
        if padding_len < 8 {
            return None;
        }

        Some(bytes[1 + padding_len + 1..].to_vec())
    }
}

#[cfg(test)]
mod test_pkcs1_v1_5_signature {
    use num_bigint::BigUint;

    use super::{PKCS1v1_5, SignaturePadding};
    use crate::digest::{Digest, SHA256};

    const BITS: usize = 1024;

    #[test]
    fn pad() {
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
    fn unpad() {
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
    fn unpad_reject_bad_start() {
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
    fn unpad_reject_bad_len() {
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
    fn unpad_reject_bad_padding() {
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
    fn unpad_reject_bad_before_prefix() {
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
    fn unpad_reject_bad_prefix() {
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
    fn unpad_reject_bad_digest() {
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
    fn unpad_reject_short_padding() {
        let prefix = <SHA256 as Digest>::ASN1_PREFIX;
        let digest = SHA256::digest(&[]);

        let signature_bytes = [&[0x01_u8] as &[u8], &[0xff; 7], &[0x00], prefix, &digest].concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid =
            PKCS1v1_5::unpad_verify::<SHA256>(10 + prefix.len() + digest.len(), &[], &signature);

        assert!(!is_valid);
    }

    #[test]
    fn unpad_min_padding() {
        let prefix = <SHA256 as Digest>::ASN1_PREFIX;
        let digest = SHA256::digest(&[]);

        let signature_bytes = [&[0x01_u8] as &[u8], &[0xff; 8], &[0x00], prefix, &digest].concat();

        let signature = BigUint::from_bytes_be(&signature_bytes);
        let is_valid =
            PKCS1v1_5::unpad_verify::<SHA256>(11 + prefix.len() + digest.len(), &[], &signature);

        assert!(is_valid);
    }
}

#[cfg(test)]
mod test_pkcs1_v1_5_encryption {
    use num_bigint::BigUint;

    use super::{EncrytionPadding, PKCS1v1_5};

    const MESSAGE: &[u8] = b"THIS IS MY PLAINTEXT";
    const BITS: usize = 1024;

    #[test]
    fn pad_exact_len() {
        assert!(PKCS1v1_5::pad(MESSAGE.len() + 11, MESSAGE).is_some());
    }

    #[test]
    fn pad_reject_short_block() {
        assert!(PKCS1v1_5::pad(MESSAGE.len() + 10, MESSAGE).is_none());
    }

    #[test]
    fn unpad() {
        let bytes = [
            &[
                0x02_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xca, 0xfe,
                0xde, 0xad, 0xbe, 0xef, 0x00,
            ] as &[u8],
            MESSAGE,
        ]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(
            PKCS1v1_5::unpad(19 + MESSAGE.len(), &padded).unwrap(),
            MESSAGE
        );
    }
    #[test]
    fn unpad_reject_bad_len() {
        let bytes = [
            &[
                0x02_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xca, 0xfe,
                0xde, 0xad, 0xbe, 0xef, 0x00,
            ] as &[u8],
            MESSAGE,
        ]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(PKCS1v1_5::unpad(123, &padded), None);
    }

    #[test]
    fn unpad_reject_bad_block_type() {
        let bytes = [
            &[
                0x13_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xca, 0xfe,
                0xde, 0xad, 0xbe, 0xef, 0x00,
            ] as &[u8],
            MESSAGE,
        ]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(PKCS1v1_5::unpad(19 + MESSAGE.len(), &padded), None);
    }

    #[test]
    fn unpad_reject_short_padding() {
        let bytes = [
            &[0x02_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0x00] as &[u8],
            MESSAGE,
        ]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(PKCS1v1_5::unpad(10 + MESSAGE.len(), &padded), None);
    }

    #[test]
    fn unpad_exact_padding() {
        let bytes = [
            &[
                0x02_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0x00,
            ] as &[u8],
            MESSAGE,
        ]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(
            PKCS1v1_5::unpad(11 + MESSAGE.len(), &padded).unwrap(),
            MESSAGE
        );
    }

    #[test]
    fn unpad_reject_missing_pad_ending() {
        let bytes = [&[
            0x02_u8, 0xba, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xca, 0xfe, 0xde,
            0xad, 0xbe, 0xef,
        ] as &[u8]]
        .concat();
        let padded = BigUint::from_bytes_be(&bytes);

        assert_eq!(PKCS1v1_5::unpad(18, &padded), None);
    }

    #[test]
    fn roundtrip() {
        let padded = PKCS1v1_5::pad(BITS / 8, MESSAGE).unwrap();
        let unpadded = PKCS1v1_5::unpad(BITS / 8, &padded).unwrap();

        assert_eq!(unpadded, MESSAGE);
    }
}

#[cfg(test)]
mod test_bad_pkcs1_v1_5_signature {
    use num_bigint::BigUint;

    use super::{BadPKCS1v1_5, SignaturePadding};
    use crate::digest::{Digest, SHA256};

    const BITS: usize = 1024;

    #[test]
    fn pad() {
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
    fn unpad() {
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
    fn unpad_reject_bad_start() {
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
    fn unpad_reject_bad_len() {
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
    fn unpad_reject_bad_padding() {
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
    fn unpad_reject_bad_before_prefix() {
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
    fn unpad_reject_bad_prefix() {
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
    fn unpad_reject_bad_digest() {
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
    fn unpad_accepts_right_garbage() {
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
