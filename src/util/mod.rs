//! Various convenience utilities.

pub mod iter;

use ::std::cmp::Ordering;

/// A probability, in the [0, 1] range (although no check is enforced).
#[derive(PartialEq, PartialOrd)]
#[must_use]
pub struct Probability(pub f32);

impl Eq for Probability {}

#[allow(clippy::derive_ord_xor_partial_ord)] // SUE ME
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
#[must_use]
pub fn generate_bytes(n: usize) -> Vec<u8> {
    use rand::distributions::Standard;
    use rand::Rng;

    let rng = rand::thread_rng();
    rng.sample_iter(&Standard).take(n).collect()
}

/// Scores text based on its contents.
pub trait TextScorer {
    fn score(&self, string: &str) -> f32;
}

/// Scores according to occurrences of English's most common letters.
pub struct NaiveTextScorer;

/// Letters to count in `NaiveTextScorer`.
const ENGLISH_COMMON_LETTERS: &str = "ETAOIN SHRDLU";

impl TextScorer for NaiveTextScorer {
    fn score(&self, string: &str) -> f32 {
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
}

/// Get Unix time (seconds since Unix epoch).
///
/// # Panics
///
/// If run before Unix epoch.
#[must_use]
pub fn get_unix_time() -> u64 {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Who invented a time machine!?")
        .as_secs()
}
