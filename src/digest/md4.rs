//! [MD4](https://en.wikipedia.org/wiki/MD4) hash function.

use crate::digest::Digest;
use byteorder::{ByteOrder, LittleEndian};

const BLOCK_LENGTH: usize = 64;

fn f(x: u32, y: u32, z: u32) -> u32 {
  (x & y) | ((!x) & z)
}

fn ff(x: &[u32], a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32) {
  *a = (*a)
    .wrapping_add(f(b, c, d))
    .wrapping_add(x[k])
    .rotate_left(s)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
  (x & y) | (x & z) | (y & z)
}

fn gg(x: &[u32], a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32) {
  *a = (*a)
    .wrapping_add(g(b, c, d))
    .wrapping_add(x[k])
    .wrapping_add(0x5A827999)
    .rotate_left(s)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
  x ^ y ^ z
}

fn hh(x: &[u32], a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32) {
  *a = (*a)
    .wrapping_add(h(b, c, d))
    .wrapping_add(x[k])
    .wrapping_add(0x6ED9EBA1)
    .rotate_left(s)
}

/// [MD4](https://en.wikipedia.org/wiki/MD4) hash implementation.
pub struct MD4 {
  h0: u32,
  h1: u32,
  h2: u32,
  h3: u32,
  block_count: u64,
  current_block: Vec<u8>,
}

impl MD4 {
  /// Create a reset MD4 instance (initial values)
  pub fn new() -> MD4 {
    MD4 {
      h0: 0x67452301,
      h1: 0xefcdab89,
      h2: 0x98badcfe,
      h3: 0x10325476,
      block_count: 0,
      current_block: vec![],
    }
  }

  /// Create a MD4 from specific internal-state values
  pub fn new_from_state(
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    block_count: u64,
    current_block: &[u8],
  ) -> MD4 {
    MD4 {
      h0,
      h1,
      h2,
      h3,
      block_count,
      current_block: current_block.to_vec(),
    }
  }

  /// Create a MD4 instance from a previous hash value (the value obtained
  /// after calling `.finalize()` on it)
  pub fn new_from_hash(hash: [u8; 16], block_count: u64) -> MD4 {
    MD4 {
      h0: LittleEndian::read_u32(&hash[0..4]),
      h1: LittleEndian::read_u32(&hash[4..8]),
      h2: LittleEndian::read_u32(&hash[8..12]),
      h3: LittleEndian::read_u32(&hash[12..16]),
      block_count,
      current_block: vec![],
    }
  }
}

impl Digest for MD4 {
  type Output = [u8; 16];

  fn update(&mut self, message: &[u8]) {
    let blocks = [&self.current_block, message].concat();

    self.current_block = vec![];

    for chunk in blocks.chunks(BLOCK_LENGTH) {
      if chunk.len() != BLOCK_LENGTH {
        self.current_block = chunk.to_vec();
        break;
      }

      let mut w = [0u32; 16];

      for i in 0..16 {
        w[i] = LittleEndian::read_u32(&chunk[4 * i..4 * (i + 1)]);
      }

      let mut a = self.h0;
      let mut b = self.h1;
      let mut c = self.h2;
      let mut d = self.h3;

      // Round 1
      ff(&w, &mut a, b, c, d, 0, 3);
      ff(&w, &mut d, a, b, c, 1, 7);
      ff(&w, &mut c, d, a, b, 2, 11);
      ff(&w, &mut b, c, d, a, 3, 19);

      ff(&w, &mut a, b, c, d, 4, 3);
      ff(&w, &mut d, a, b, c, 5, 7);
      ff(&w, &mut c, d, a, b, 6, 11);
      ff(&w, &mut b, c, d, a, 7, 19);

      ff(&w, &mut a, b, c, d, 8, 3);
      ff(&w, &mut d, a, b, c, 9, 7);
      ff(&w, &mut c, d, a, b, 10, 11);
      ff(&w, &mut b, c, d, a, 11, 19);

      ff(&w, &mut a, b, c, d, 12, 3);
      ff(&w, &mut d, a, b, c, 13, 7);
      ff(&w, &mut c, d, a, b, 14, 11);
      ff(&w, &mut b, c, d, a, 15, 19);

      // Round 2
      gg(&w, &mut a, b, c, d, 0, 3);
      gg(&w, &mut d, a, b, c, 4, 5);
      gg(&w, &mut c, d, a, b, 8, 9);
      gg(&w, &mut b, c, d, a, 12, 13);

      gg(&w, &mut a, b, c, d, 1, 3);
      gg(&w, &mut d, a, b, c, 5, 5);
      gg(&w, &mut c, d, a, b, 9, 9);
      gg(&w, &mut b, c, d, a, 13, 13);

      gg(&w, &mut a, b, c, d, 2, 3);
      gg(&w, &mut d, a, b, c, 6, 5);
      gg(&w, &mut c, d, a, b, 10, 9);
      gg(&w, &mut b, c, d, a, 14, 13);

      gg(&w, &mut a, b, c, d, 3, 3);
      gg(&w, &mut d, a, b, c, 7, 5);
      gg(&w, &mut c, d, a, b, 11, 9);
      gg(&w, &mut b, c, d, a, 15, 13);

      // Round 3
      hh(&w, &mut a, b, c, d, 0, 3);
      hh(&w, &mut d, a, b, c, 8, 9);
      hh(&w, &mut c, d, a, b, 4, 11);
      hh(&w, &mut b, c, d, a, 12, 15);

      hh(&w, &mut a, b, c, d, 2, 3);
      hh(&w, &mut d, a, b, c, 10, 9);
      hh(&w, &mut c, d, a, b, 6, 11);
      hh(&w, &mut b, c, d, a, 14, 15);

      hh(&w, &mut a, b, c, d, 1, 3);
      hh(&w, &mut d, a, b, c, 9, 9);
      hh(&w, &mut c, d, a, b, 5, 11);
      hh(&w, &mut b, c, d, a, 13, 15);

      hh(&w, &mut a, b, c, d, 3, 3);
      hh(&w, &mut d, a, b, c, 11, 9);
      hh(&w, &mut c, d, a, b, 7, 11);
      hh(&w, &mut b, c, d, a, 15, 15);

      self.h0 = self.h0.wrapping_add(a);
      self.h1 = self.h1.wrapping_add(b);
      self.h2 = self.h2.wrapping_add(c);
      self.h3 = self.h3.wrapping_add(d);
      self.block_count += 1;
    }
  }

  fn finalize(mut self) -> [u8; 16] {
    let message_len = self.block_count * BLOCK_LENGTH as u64 + self.current_block.len() as u64;
    let mut ml = [0; 8];
    LittleEndian::write_u64(&mut ml, 8 * message_len as u64);

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

    let mut hh = [0; 16];

    LittleEndian::write_u32(&mut hh[0..4], self.h0);
    LittleEndian::write_u32(&mut hh[4..8], self.h1);
    LittleEndian::write_u32(&mut hh[8..12], self.h2);
    LittleEndian::write_u32(&mut hh[12..16], self.h3);

    hh
  }
}

#[cfg(test)]
mod test {
  use crate::digest::{Digest, MD4};

  const EMPTY_STRING_MD4: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
  ];

  const ABC_STRING_MD4: [u8; 16] = [
    0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d,
  ];

  const SET1_SOLUTION_6_BYTES: &[u8] = include_bytes!("../../tests/set1/6.solution.txt");

  const SET1_SOLUTION_6_MD4: [u8; 16] = [
    0x39, 0xc5, 0x08, 0x3f, 0x88, 0x79, 0xe4, 0xe3, 0x6e, 0xee, 0xdc, 0x84, 0xbb, 0x01, 0xed, 0x9f,
  ];

  #[test]
  fn basic_md4() {
    // ""
    assert_eq!(MD4::new().finalize(), EMPTY_STRING_MD4);

    let mut digest = MD4::new();
    digest.update("".as_bytes());
    assert_eq!(digest.finalize(), EMPTY_STRING_MD4);

    assert_eq!(MD4::new().chain("".as_bytes()).finalize(), EMPTY_STRING_MD4);

    // "abc"
    let mut digest = MD4::new();
    digest.update("abc".as_bytes());
    assert_eq!(digest.finalize(), ABC_STRING_MD4);

    let mut digest = MD4::new();
    digest.update("ab".as_bytes());
    digest.update("c".as_bytes());
    assert_eq!(digest.finalize(), ABC_STRING_MD4);

    assert_eq!(
      MD4::new().chain("abc".as_bytes()).finalize(),
      ABC_STRING_MD4
    );

    assert_eq!(
      MD4::new()
        .chain("ab".as_bytes())
        .chain("c".as_bytes())
        .finalize(),
      ABC_STRING_MD4
    );

    // Set 1 Challenge 6 Solution File
    let mut digest = MD4::new();
    digest.update(SET1_SOLUTION_6_BYTES);
    assert_eq!(digest.finalize(), SET1_SOLUTION_6_MD4);

    let mut digest = MD4::new();
    digest.update(&SET1_SOLUTION_6_BYTES[0..50]);
    digest.update(&SET1_SOLUTION_6_BYTES[50..]);
    assert_eq!(digest.finalize(), SET1_SOLUTION_6_MD4);

    assert_eq!(
      MD4::new().chain(SET1_SOLUTION_6_BYTES).finalize(),
      SET1_SOLUTION_6_MD4
    );

    assert_eq!(
      MD4::new()
        .chain(&SET1_SOLUTION_6_BYTES[0..50])
        .chain(&SET1_SOLUTION_6_BYTES[50..])
        .finalize(),
      SET1_SOLUTION_6_MD4
    );
  }
}
