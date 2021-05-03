//! [SHA-256](https://en.wikipedia.org/wiki/SHA-256) hash function.

use crate::digest::{Digest, ExtensibleDigest};
use byteorder::{BigEndian, ByteOrder};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// [SHA-256](https://en.wikipedia.org/wiki/SHA-256) hash implementation.
#[must_use]
pub struct SHA256 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    block_count: u64,
    current_block: Vec<u8>,
}

impl SHA256 {
    /// Create a reset SHA256 instance (initial values).
    pub const fn new() -> SHA256 {
        SHA256 {
            h0: 0x6a09e667,
            h1: 0xbb67ae85,
            h2: 0x3c6ef372,
            h3: 0xa54ff53a,
            h4: 0x510e527f,
            h5: 0x9b05688c,
            h6: 0x1f83d9ab,
            h7: 0x5be0cd19,
            block_count: 0,
            current_block: vec![],
        }
    }

    /// Create a SHA256 from specific internal-state values.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_state(
        h0: u32,
        h1: u32,
        h2: u32,
        h3: u32,
        h4: u32,
        h5: u32,
        h6: u32,
        h7: u32,
        block_count: u64,
        current_block: &[u8],
    ) -> SHA256 {
        SHA256 {
            h0,
            h1,
            h2,
            h3,
            h4,
            h5,
            h6,
            h7,
            block_count,
            current_block: current_block.to_vec(),
        }
    }

    /// Create a SHA256 instance from a previous hash value (the value obtained
    /// after calling `.finalize()` on it).
    fn new_from_hash(hash: [u8; 32], block_count: u64) -> SHA256 {
        SHA256 {
            h0: BigEndian::read_u32(&hash[0..4]),
            h1: BigEndian::read_u32(&hash[4..8]),
            h2: BigEndian::read_u32(&hash[8..12]),
            h3: BigEndian::read_u32(&hash[12..16]),
            h4: BigEndian::read_u32(&hash[16..20]),
            h5: BigEndian::read_u32(&hash[20..24]),
            h6: BigEndian::read_u32(&hash[24..28]),
            h7: BigEndian::read_u32(&hash[28..32]),
            block_count,
            current_block: vec![],
        }
    }
}

impl Default for SHA256 {
    fn default() -> Self {
        SHA256::new()
    }
}

impl Digest for SHA256 {
    const OUTPUT_LENGTH: usize = 32;
    const BLOCK_LENGTH: usize = 64;

    type Output = [u8; Self::OUTPUT_LENGTH];

    #[allow(clippy::many_single_char_names)]
    fn update(&mut self, message: &[u8]) {
        let blocks = [&self.current_block, message].concat();

        self.current_block = vec![];

        for chunk in blocks.chunks(Self::BLOCK_LENGTH) {
            if chunk.len() != Self::BLOCK_LENGTH {
                self.current_block = chunk.to_vec();
                break;
            }

            let mut w = [0_u32; 64];

            for i in 0..16 {
                w[i] = BigEndian::read_u32(&chunk[4 * i..4 * (i + 1)]);
            }

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;
            let mut f = self.h5;
            let mut g = self.h6;
            let mut h = self.h7;

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.h0 = self.h0.wrapping_add(a);
            self.h1 = self.h1.wrapping_add(b);
            self.h2 = self.h2.wrapping_add(c);
            self.h3 = self.h3.wrapping_add(d);
            self.h4 = self.h4.wrapping_add(e);
            self.h5 = self.h5.wrapping_add(f);
            self.h6 = self.h6.wrapping_add(g);
            self.h7 = self.h7.wrapping_add(h);
            self.block_count += 1;
        }
    }

    fn finalize(mut self) -> Self::Output {
        let message_len =
            self.block_count * Self::BLOCK_LENGTH as u64 + self.current_block.len() as u64;
        let mut ml = [0; 8];
        BigEndian::write_u64(&mut ml, 8 * message_len as u64);

        // Add a 1 bit (message end)
        self.update(&[0x80]);

        // Add zero-padding
        let padding_len = Self::BLOCK_LENGTH
            - ((1 + ml.len() as u64 + message_len) % Self::BLOCK_LENGTH as u64) as usize;
        self.update(&vec![0; padding_len as usize]);

        // Add message length
        self.update(&ml);

        // Output
        assert_eq!(self.current_block, &[]);

        let mut hh = [0; Self::OUTPUT_LENGTH];

        BigEndian::write_u32(&mut hh[0..4], self.h0);
        BigEndian::write_u32(&mut hh[4..8], self.h1);
        BigEndian::write_u32(&mut hh[8..12], self.h2);
        BigEndian::write_u32(&mut hh[12..16], self.h3);
        BigEndian::write_u32(&mut hh[16..20], self.h4);
        BigEndian::write_u32(&mut hh[20..24], self.h5);
        BigEndian::write_u32(&mut hh[24..28], self.h6);
        BigEndian::write_u32(&mut hh[28..32], self.h7);

        hh
    }
}

impl ExtensibleDigest for SHA256 {
    fn extend_digest(
        digest_output: Self::Output,
        guessed_payload_length: usize,
    ) -> (Self, Vec<u8>) {
        let mut ml = [0; 8];
        BigEndian::write_u64(&mut ml, 8 * guessed_payload_length as u64);

        let guessed_padding_len =
            Self::BLOCK_LENGTH - ((1 + ml.len() + guessed_payload_length) % Self::BLOCK_LENGTH);
        let guessed_block_len = 1 + guessed_payload_length as u64 / Self::BLOCK_LENGTH as u64;

        let cracked_digest = SHA256::new_from_hash(digest_output, guessed_block_len);
        let cracked_payload = [[0x80].as_ref(), &vec![0; guessed_padding_len], &ml].concat();

        (cracked_digest, cracked_payload)
    }
}

#[cfg(test)]
mod test {
    use crate::digest::{Digest, SHA256};

    const EMPTY_STRING_SHA256: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    const ASDF_STRING_SHA256: [u8; 32] = [
        0xf0, 0xe4, 0xc2, 0xf7, 0x6c, 0x58, 0x91, 0x6e, 0xc2, 0x58, 0xf2, 0x46, 0x85, 0x1b, 0xea,
        0x09, 0x1d, 0x14, 0xd4, 0x24, 0x7a, 0x2f, 0xc3, 0xe1, 0x86, 0x94, 0x46, 0x1b, 0x18, 0x16,
        0xe1, 0x3b,
    ];

    const SET1_SOLUTION_6_BYTES: &[u8] = include_bytes!("../../tests/set1/6.solution.txt");

    const SET1_SOLUTION_6_SHA256: [u8; 32] = [
        0x24, 0xdf, 0x84, 0x53, 0x3f, 0xc2, 0x77, 0x84, 0x95, 0x57, 0x7c, 0x84, 0x4b, 0xcf, 0x3f,
        0xe1, 0xd4, 0xd1, 0x7c, 0x68, 0xd8, 0xc5, 0xcb, 0xc5, 0xa3, 0x08, 0x28, 0x6d, 0xb5, 0x8c,
        0x69, 0xb6,
    ];

    #[test]
    fn basic_sha256() {
        // ""
        assert_eq!(SHA256::new().finalize(), EMPTY_STRING_SHA256);

        let mut digest = SHA256::new();
        digest.update(b"");
        assert_eq!(digest.finalize(), EMPTY_STRING_SHA256);

        assert_eq!(SHA256::new().chain(b"").finalize(), EMPTY_STRING_SHA256);

        // "asdf"
        let mut digest = SHA256::new();
        digest.update(b"asdf");
        assert_eq!(digest.finalize(), ASDF_STRING_SHA256);

        let mut digest = SHA256::new();
        digest.update(b"as");
        digest.update(b"df");
        assert_eq!(digest.finalize(), ASDF_STRING_SHA256);

        assert_eq!(SHA256::new().chain(b"asdf").finalize(), ASDF_STRING_SHA256);

        assert_eq!(
            SHA256::new().chain(b"as").chain(b"df").finalize(),
            ASDF_STRING_SHA256
        );

        // Set 1 Challenge 6 Solution File
        let mut digest = SHA256::new();
        digest.update(SET1_SOLUTION_6_BYTES);
        assert_eq!(digest.finalize(), SET1_SOLUTION_6_SHA256);

        let mut digest = SHA256::new();
        digest.update(&SET1_SOLUTION_6_BYTES[0..50]);
        digest.update(&SET1_SOLUTION_6_BYTES[50..]);
        assert_eq!(digest.finalize(), SET1_SOLUTION_6_SHA256);

        assert_eq!(
            SHA256::new().chain(SET1_SOLUTION_6_BYTES).finalize(),
            SET1_SOLUTION_6_SHA256
        );

        assert_eq!(
            SHA256::new()
                .chain(&SET1_SOLUTION_6_BYTES[0..50])
                .chain(&SET1_SOLUTION_6_BYTES[50..])
                .finalize(),
            SET1_SOLUTION_6_SHA256
        );
    }
}
