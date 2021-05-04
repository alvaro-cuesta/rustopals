use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};

/// Does mathematical modulo (similar to remainder `%`).
///
/// The difference is that `-1 % 5 = -1`, but `-1 mod 5 = 4`.
fn math_mod(x: &BigInt, n: &BigUint) -> BigUint {
    let n_bigint = n.to_bigint().unwrap();

    (((x % &n_bigint) + &n_bigint) % &n_bigint)
        .to_biguint()
        .unwrap()
}

/// [Extended Eucliean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
///
/// Naive implementation.
///
/// # Panics
///
/// If `a` >= `b`.
#[allow(clippy::many_single_char_names)]
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
pub fn inv_mod(a: BigUint, n: &BigUint) -> Option<BigUint> {
    assert!(&a < n);

    let (g, x, _) = egcd(BigInt::from(a), n.to_bigint().unwrap());

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
