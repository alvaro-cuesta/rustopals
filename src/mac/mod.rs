//! [Message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code)
//! implementations and related utilities.

use crate::digest::Digest;
use crate::util::iter::Xorable;
use std::iter;

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

/// [HMAC](https://en.wikipedia.org/wiki/HMAC) implementation.
#[must_use]
pub fn hmac<D: Digest>(key: &[u8], message: &[u8]) -> D::Output {
    let key = if key.len() > D::BLOCK_LENGTH {
        D::digest(key).as_ref().to_vec()
    } else {
        key.to_vec()
    };

    let key = if key.len() < D::BLOCK_LENGTH {
        let padding_len = D::BLOCK_LENGTH - key.len();
        [key, vec![0; padding_len]].concat()
    } else {
        key
    };

    let o_key_pad = key.iter().xor(iter::repeat(0x5c)).collect::<Vec<_>>();
    let i_key_pad = key.iter().xor(iter::repeat(0x36)).collect::<Vec<_>>();

    let inner_hash = <D as Default>::default()
        .chain(&i_key_pad)
        .chain(message)
        .finalize();

    <D as Default>::default()
        .chain(&o_key_pad)
        .chain(inner_hash.as_ref())
        .finalize()
}

#[cfg(test)]
mod test {
    use super::hmac;
    use crate::digest::SHA256;

    // From https://tools.ietf.org/html/rfc4231
    #[test]
    fn test_hmac_sha256() {
        {
            const KEY: &[u8] = &[0x0b; 20];

            const MESSAGE: &[u8] = b"Hi There";

            const EXPECTED: &[u8] = &[
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }

        {
            const KEY: &[u8] = b"Jefe";

            const MESSAGE: &[u8] = b"what do ya want for nothing?";

            const EXPECTED: &[u8] = &[
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }

        {
            const KEY: &[u8] = &[0xaa; 20];

            const MESSAGE: &[u8] = &[0xdd; 50];

            const EXPECTED: &[u8] = &[
                0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
                0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
                0xce, 0xd5, 0x65, 0xfe,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }

        {
            const KEY: &[u8] = &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            ];

            const MESSAGE: &[u8] = &[0xcd; 50];

            const EXPECTED: &[u8] = &[
                0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2,
                0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4,
                0x67, 0x29, 0x66, 0x5b,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }

        {
            const KEY: &[u8] = &[0x0c; 20];

            const MESSAGE: &[u8] = b"Test With Truncation";

            const EXPECTED: &[u8] = &[
                0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
                0x55, 0x2b,
            ];

            assert_eq!(&hmac::<SHA256>(KEY, MESSAGE)[..16], EXPECTED);
        }

        {
            const KEY: &[u8] = &[0xaa; 131];

            const MESSAGE: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";

            const EXPECTED: &[u8] = &[
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
                0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
                0x0e, 0xe3, 0x7f, 0x54,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }

        {
            const KEY: &[u8] = &[0xaa; 131];

            const MESSAGE: &[u8] = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

            const EXPECTED: &[u8] = &[
                0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0,
                0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53,
                0x5c, 0x3a, 0x35, 0xe2,
            ];

            assert_eq!(hmac::<SHA256>(KEY, MESSAGE), EXPECTED);
        }
    }
}
