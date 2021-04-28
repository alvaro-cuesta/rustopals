//! Various utilities.

pub mod iter;

use ::std::cmp::Ordering;

/// A probability, in the [0, 1] range (although no check is enforced).
#[derive(PartialEq, PartialOrd)]
pub struct Probability(pub f32);

impl Eq for Probability {}

impl Ord for Probability {
  fn cmp(&self, other: &Probability) -> Ordering {
    let &Probability(x) = self;
    let &Probability(y) = other;

    if x > y {
      Ordering::Greater
    } else if x < y {
      Ordering::Less
    } else if x.is_finite() && y.is_finite() {
      Ordering::Equal
    } else {
      panic!("Trying to Ord NaN");
    }
  }
}

/// Generate `n` random bytes.
pub fn generate_bytes(n: usize) -> Vec<u8> {
  use rand::distributions::Standard;
  use rand::Rng;

  let rng = rand::thread_rng();
  rng.sample_iter(&Standard).take(n).collect()
}

const ENGLISH_COMMON_LETTERS: &str = "ETAOIN SHRDLU";

pub(crate) fn score_string(string: &str) -> f32 {
  use iter::Occurrenceable;

  let input_occurrences = string
    .chars()
    .map(|ch| ch.to_uppercase().collect::<String>())
    .occurrences();

  let occurrences: usize = ENGLISH_COMMON_LETTERS
    .chars()
    .map(|x| input_occurrences.get(&x.to_string()).unwrap_or(&0))
    .sum();

  occurrences as f32 / ENGLISH_COMMON_LETTERS.len() as f32
}
