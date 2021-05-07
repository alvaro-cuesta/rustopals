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

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

/// Does mathematical modulo (similar to remainder `%`).
///
/// The difference is that `-1 % 5 = -1`, but `-1 mod 5 = 4`.
#[must_use]
pub fn math_mod(x: &BigInt, n: &BigUint) -> BigUint {
    let n_bigint = BigInt::from(n.clone());

    (((x % &n_bigint) + &n_bigint) % &n_bigint)
        .to_biguint()
        .expect("Already ensure non-negative sign")
}

/// [Extended Eucliean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
///
/// Naive implementation.
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        return (b, BigInt::from(0_usize), BigInt::from(1_usize));
    }

    let (g, y, x) = egcd(&b % &a, a.clone());

    (g, x - (b / a) * &y, y)
}

/// [Modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse)
///
/// Naive implementation.
#[must_use]
pub fn inv_mod(a: BigUint, n: &BigUint) -> Option<BigUint> {
    let (g, x, _) = egcd(BigInt::from(a), BigInt::from(n.clone()));

    if !g.is_one() {
        return None;
    }

    Some(math_mod(&x, n))
}

#[cfg(test)]
mod test {
    use num_bigint::{BigInt, BigUint};

    use super::{egcd, inv_mod};

    #[test]
    fn test_egcd() {
        let a = BigInt::from(3_usize);
        let b = BigInt::from(26_usize);
        let (gcd, x, y) = egcd(a.clone(), b.clone());

        assert_eq!(gcd, BigInt::from(1_usize));
        assert_eq!(x, BigInt::from(9_usize));
        assert_eq!(y, BigInt::from(-1_isize));
        assert_eq!(a * x + b * y, gcd);
    }
    #[test]
    fn test_inv_mod() {
        assert_eq!(
            inv_mod(BigUint::from(17_usize), &BigUint::from(3120_usize)),
            Some(BigUint::from(2753_usize)),
        );
    }
}
