//! [SHA-1](https://en.wikipedia.org/wiki/SHA-1) hash function.

use crate::digest::Digest;
use byteorder::{BigEndian, ByteOrder};

const BLOCK_LENGTH: usize = 64;

/// [SHA-1](https://en.wikipedia.org/wiki/SHA-1) hash implementation.
pub struct SHA1 {
  h0: u32,
  h1: u32,
  h2: u32,
  h3: u32,
  h4: u32,
  block_count: u64,
  current_block: Vec<u8>,
}

impl SHA1 {
  /// Create a reset SHA1 instance (initial values)
  pub fn new() -> SHA1 {
    SHA1 {
      h0: 0x67452301,
      h1: 0xEFCDAB89,
      h2: 0x98BADCFE,
      h3: 0x10325476,
      h4: 0xC3D2E1F0,
      block_count: 0,
      current_block: vec![],
    }
  }

  /// Create a SHA1 from specific internal-state values
  pub fn new_from_state(
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    block_count: u64,
    current_block: &[u8],
  ) -> SHA1 {
    SHA1 {
      h0,
      h1,
      h2,
      h3,
      h4,
      block_count,
      current_block: current_block.to_vec(),
    }
  }

  /// Create a SHA1 instance from a previous hash value (the value obtained
  /// after calling `.finalize()` on it)
  pub fn new_from_hash(hash: [u8; 20], block_count: u64) -> SHA1 {
    SHA1 {
      h0: BigEndian::read_u32(&hash[0..4]),
      h1: BigEndian::read_u32(&hash[4..8]),
      h2: BigEndian::read_u32(&hash[8..12]),
      h3: BigEndian::read_u32(&hash[12..16]),
      h4: BigEndian::read_u32(&hash[16..20]),
      block_count,
      current_block: vec![],
    }
  }
}

impl Digest for SHA1 {
  type Output = [u8; 20];

  fn update(&mut self, message: &[u8]) {
    let blocks = [&self.current_block, message].concat();

    self.current_block = vec![];

    for chunk in blocks.chunks(BLOCK_LENGTH) {
      if chunk.len() != BLOCK_LENGTH {
        self.current_block = chunk.to_vec();
        break;
      }

      let mut w = [0u32; 80];

      for i in 0..16 {
        w[i] = BigEndian::read_u32(&chunk[4 * i..4 * (i + 1)]);
      }

      for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
      }

      let mut a = self.h0;
      let mut b = self.h1;
      let mut c = self.h2;
      let mut d = self.h3;
      let mut e = self.h4;

      for i in 0..80 {
        let (f, k) = if i < 20 {
          ((b & c) | ((!b) & d), 0x5A827999)
        } else if i < 40 {
          (b ^ c ^ d, 0x6ED9EBA1)
        } else if i < 60 {
          ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
        } else {
          (b ^ c ^ d, 0xCA62C1D6)
        };

        let temp = (a.rotate_left(5))
          .wrapping_add(f)
          .wrapping_add(e)
          .wrapping_add(k)
          .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
      }

      self.h0 = self.h0.wrapping_add(a);
      self.h1 = self.h1.wrapping_add(b);
      self.h2 = self.h2.wrapping_add(c);
      self.h3 = self.h3.wrapping_add(d);
      self.h4 = self.h4.wrapping_add(e);
      self.block_count += 1;
    }
  }

  fn finalize(mut self) -> [u8; 20] {
    let message_len = self.block_count * BLOCK_LENGTH as u64 + self.current_block.len() as u64;
    let mut ml = [0; 8];
    BigEndian::write_u64(&mut ml, 8 * message_len as u64);

    // Add a 1 bit (message end)
    self.update(&[0x80]);

    // Add zero-padding
    let padding_len =
      BLOCK_LENGTH - ((1 + ml.len() as u64 + message_len) % BLOCK_LENGTH as u64) as usize;
    self.update(&vec![0; padding_len as usize]);

    // Add message length
    self.update(&ml);

    // Output
    assert_eq!(self.current_block, &[]);

    let mut hh = [0; 20];

    BigEndian::write_u32(&mut hh[0..4], self.h0);
    BigEndian::write_u32(&mut hh[4..8], self.h1);
    BigEndian::write_u32(&mut hh[8..12], self.h2);
    BigEndian::write_u32(&mut hh[12..16], self.h3);
    BigEndian::write_u32(&mut hh[16..20], self.h4);

    hh
  }
}

#[cfg(test)]
mod test {
  use crate::digest::{Digest, SHA1};

  const EMPTY_STRING_SHA1: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
  ];

  const ASDF_STRING_SHA1: [u8; 20] = [
    0x3d, 0xa5, 0x41, 0x55, 0x99, 0x18, 0xa8, 0x08, 0xc2, 0x40, 0x2b, 0xba, 0x50, 0x12, 0xf6, 0xc6,
    0x0b, 0x27, 0x66, 0x1c,
  ];

  const SET1_SOLUTION_6_BYTES: &[u8] = include_bytes!("../../tests/set1/6.solution.txt");

  const SET1_SOLUTION_6_SHA1: [u8; 20] = [
    0xd7, 0x9e, 0xc2, 0x35, 0xb7, 0x63, 0x28, 0x9e, 0x49, 0x6a, 0xc3, 0xe0, 0x97, 0x26, 0x07, 0x32,
    0x5c, 0x3f, 0x91, 0xa6,
  ];

  #[test]
  fn basic_sha1() {
    // ""
    assert_eq!(SHA1::new().finalize(), EMPTY_STRING_SHA1);

    let mut digest = SHA1::new();
    digest.update("".as_bytes());
    assert_eq!(digest.finalize(), EMPTY_STRING_SHA1);

    assert_eq!(
      SHA1::new().chain("".as_bytes()).finalize(),
      EMPTY_STRING_SHA1
    );

    // "asdf"
    let mut digest = SHA1::new();
    digest.update("asdf".as_bytes());
    assert_eq!(digest.finalize(), ASDF_STRING_SHA1);

    let mut digest = SHA1::new();
    digest.update("as".as_bytes());
    digest.update("df".as_bytes());
    assert_eq!(digest.finalize(), ASDF_STRING_SHA1);

    assert_eq!(
      SHA1::new().chain("asdf".as_bytes()).finalize(),
      ASDF_STRING_SHA1
    );

    assert_eq!(
      SHA1::new()
        .chain("as".as_bytes())
        .chain("df".as_bytes())
        .finalize(),
      ASDF_STRING_SHA1
    );

    // Set 1 Challenge 6 Solution File
    let mut digest = SHA1::new();
    digest.update(SET1_SOLUTION_6_BYTES);
    assert_eq!(digest.finalize(), SET1_SOLUTION_6_SHA1);

    let mut digest = SHA1::new();
    digest.update(&SET1_SOLUTION_6_BYTES[0..50]);
    digest.update(&SET1_SOLUTION_6_BYTES[50..]);
    assert_eq!(digest.finalize(), SET1_SOLUTION_6_SHA1);

    assert_eq!(
      SHA1::new().chain(SET1_SOLUTION_6_BYTES).finalize(),
      SET1_SOLUTION_6_SHA1
    );

    assert_eq!(
      SHA1::new()
        .chain(&SET1_SOLUTION_6_BYTES[0..50])
        .chain(&SET1_SOLUTION_6_BYTES[50..])
        .finalize(),
      SET1_SOLUTION_6_SHA1
    );
  }
}
