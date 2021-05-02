//! [Pseudo-random number generators](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
//! and related utilities.

use rand::{RngCore, SeedableRng};

const MERSENNE_TEMPER_MASK_1: u32 = 0x9d2c5680;
const MERSENNE_TEMPER_MASK_2: u32 = 0xefc60000;

/// [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) (MT19937) over 32 bits.
#[derive(Clone)]
pub struct MT19937 {
  state: [u32; 624],
  index: usize,
}

impl MT19937 {
  pub fn new(seed: u32) -> MT19937 {
    use byteorder::{ByteOrder, NativeEndian};

    let mut seed_bytes = [0; 4];
    NativeEndian::write_u32(&mut seed_bytes, seed);

    MT19937::new_from_bytes(seed_bytes)
  }

  pub fn new_from_bytes(seed: [u8; 4]) -> MT19937 {
    SeedableRng::from_seed(seed)
  }

  pub fn new_unseeded() -> MT19937 {
    use std::time::SystemTime;

    let now = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .unwrap()
      .as_secs();

    MT19937::new(now as u32)
  }

  pub fn from_tap(tap: &[u32]) -> MT19937 {
    let mut state = [0u32; 624];

    for i in 0..624 {
      let mut y = tap[i];

      y ^= y >> 18;
      y ^= (y << 15) & MERSENNE_TEMPER_MASK_2;
      y = {
        let mut t = y;
        for _ in 0..5 {
          t = y ^ (t << 7) & MERSENNE_TEMPER_MASK_1;
        }
        t
      };
      y = {
        let mut t = y;
        t = y ^ (t >> 11);
        t = y ^ (t >> 11);
        t
      };

      state[i] = y;
    }

    MT19937 {
      state: state,
      index: 0,
    }
  }

  fn initial_state(seed: [u8; 4]) -> [u32; 624] {
    use byteorder::{ByteOrder, NativeEndian};

    let seed = NativeEndian::read_u32(&seed);

    let mut state = [0u32; 624];

    state[0] = seed;
    for i in 1..624 {
      state[i] = (0x6c078965u32)
        .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
        .wrapping_add(i as u32);
    }

    state
  }

  fn generate_numbers(&mut self) {
    for i in 0..624 {
      let y = (self.state[i] & 0x80000000) + (self.state[(i + 1) % 624] & 0x7fffffff);

      self.state[i] = self.state[(i + 397) % 624] ^ (y >> 1);

      if (y % 2) != 0 {
        self.state[i] = self.state[i] ^ 0x9908b0df;
      }
    }
  }
}

impl RngCore for MT19937 {
  fn next_u32(&mut self) -> u32 {
    if self.index == 0 {
      self.generate_numbers()
    }

    let mut y = self.state[self.index];

    y ^= y >> 11;
    y ^= (y << 7) & MERSENNE_TEMPER_MASK_1;
    y ^= (y << 15) & MERSENNE_TEMPER_MASK_2;
    y ^= y >> 18;

    self.index = (self.index + 1) % 624;

    y
  }

  fn next_u64(&mut self) -> u64 {
    rand_core::impls::next_u64_via_u32(self)
  }

  fn fill_bytes(&mut self, dest: &mut [u8]) {
    rand_core::impls::fill_bytes_via_next(self, dest)
  }

  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
    Ok(rand_core::impls::fill_bytes_via_next(self, dest))
  }
}

impl SeedableRng for MT19937 {
  type Seed = [u8; 4];

  fn from_seed(seed: [u8; 4]) -> MT19937 {
    MT19937 {
      state: MT19937::initial_state(seed),
      index: 0,
    }
  }
}
