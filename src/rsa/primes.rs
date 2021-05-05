use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use rand::thread_rng;

const FIRST_PRIMES_COUNT: usize = 2048;
const FERMAT_ROUNDS: usize = 5;
const RABIN_MILLER_K: usize = 128; // Probability of false-positive is 2^(-k)

pub static FIRST_PRIMES: Lazy<Vec<BigUint>> = Lazy::new(|| {
    let mut primes = Vec::with_capacity(FIRST_PRIMES_COUNT);

    primes.push(2_usize);

    for x in (3_usize..).step_by(2) {
        let is_prime = primes.iter().all(|&prime| x % prime != 0);

        if is_prime {
            primes.push(x);
        }

        if primes.len() == FIRST_PRIMES_COUNT {
            break;
        }
    }

    primes.into_iter().map(BigUint::from).collect()
});

// Basic primality test against the first few primes
fn first_primes(candidate: &BigUint) -> bool {
    FIRST_PRIMES
        .iter()
        .all(|prime| !(candidate % prime).is_zero())
}

/// [Fermat primality test](https://en.wikipedia.org/wiki/Fermat_primality_test)
fn fermat(candidate: &BigUint) -> bool {
    for _k in 0..FERMAT_ROUNDS {
        let random = thread_rng().gen_biguint_below(candidate);
        let result = random.modpow(&(candidate - BigUint::one()), candidate);

        if !result.is_one() {
            return false;
        }
    }

    true
}

// Rewrite into `n = 2^s*d`
fn rewrite(mut d: BigUint) -> (BigUint, BigUint) {
    let mut s = BigUint::zero();
    let one = BigUint::one();

    while d.is_even() {
        d >>= 1;
        s += &one;
    }

    (s, d)
}

// [Rabin-Miller primality test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
fn rabin_miller(candidate: &BigUint) -> bool {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = &one + &one;

    if candidate == &two {
        return true;
    } else if candidate.is_even() {
        return false;
    }

    let candidate_minus_one = candidate - &one;

    let (s, d) = rewrite(candidate_minus_one.clone());

    for _k in (0..RABIN_MILLER_K).step_by(2) {
        let basis = thread_rng().gen_biguint_range(&two, candidate);

        let mut v = basis.modpow(&d, candidate);

        if v.is_one() || v == candidate_minus_one {
            continue;
        }

        for i in num_iter::range_from(zero.clone()) {
            v = v.modpow(&two, candidate);

            if v == candidate_minus_one {
                break;
            } else if v.is_one() || i == (&s - &one) {
                return false;
            }
        }
    }

    true
}

fn gen_prime(bits: u32) -> BigUint {
    let one = BigUint::from(1_usize);
    let two = BigUint::from(2_usize);

    loop {
        let mut candidate =
            thread_rng().gen_biguint_range(&(two.pow(bits - 1) + &one), &(two.pow(bits) - &one));

        candidate.set_bit(0, true); // Set LSB to 1 to ensure the number is odd

        if !first_primes(&candidate) || !fermat(&candidate) || !rabin_miller(&candidate) {
            continue;
        }

        return candidate;
    }
}

pub fn gen_rsa_prime(bits: u32, e: &BigUint) -> BigUint {
    loop {
        let candidate = gen_prime(bits);

        if (&candidate % e).is_one() {
            continue;
        }

        return candidate;
    }
}
