use std::cmp::{max, min};

use num_bigint::BigUint;
use num_integer::Integer;
use num_iter::{range, range_from, range_inclusive};
use rustopals::rsa::{EncrytionPadding, PKCS1v1_5};

mod adversary {
    use num_bigint::BigUint;
    use rustopals::rsa::{generate_rsa_keypair, PKCS1v1_5, RSAPrivateKey, RSAPublicKey, E};

    const PLAINTEXT: &[u8] = b"kick it, CC";

    pub struct Adversary {
        priv_key: RSAPrivateKey,
        pub pub_key: RSAPublicKey,
    }

    impl Adversary {
        pub fn new(key_size: u32) -> Adversary {
            let (pub_key, priv_key) = generate_rsa_keypair(key_size, &E);

            Adversary { priv_key, pub_key }
        }

        pub fn oracle(&self, ciphertext: &BigUint) -> bool {
            self.priv_key.decrypt::<PKCS1v1_5>(ciphertext).is_some()
        }

        pub fn get_ciphertext(&self) -> BigUint {
            self.pub_key.encrypt::<PKCS1v1_5>(&PLAINTEXT).unwrap()
        }

        pub fn check_solution(plaintext: &[u8]) -> bool {
            plaintext == PLAINTEXT
        }
    }
}

use adversary::Adversary;

fn crack(key_size: u32) -> Vec<u8> {
    let adversary = Adversary::new(key_size);

    let one = BigUint::from(1_usize);
    let two = BigUint::from(2_usize);
    let three = BigUint::from(3_usize);

    let c = adversary.get_ciphertext();
    let upper_b = two.pow(8 * (adversary.pub_key.len_bytes() as u32 - 2));
    let two_b = &two * &upper_b;
    let three_b = &three * &upper_b;
    let n = &adversary.pub_key.n;

    let oracle = |s_i: &BigUint| {
        let c_prime = (&c * s_i.modpow(&adversary.pub_key.e, n)) % n;
        adversary.oracle(&c_prime)
    };

    // Step 1: Blinding
    // Since we know `c` is PKCS-conforming, we skip it by setting `s[0]` to `1`
    let mut s_prev = one.clone();
    let mut m_prev = vec![(two_b.clone(), &three_b - &one)];

    assert!(oracle(&s_prev));

    println!("s_0 = {:?}", s_prev);
    println!("m_0 = {:?}", m_prev);

    for i in 1.. {
        println!("\ni = {}", i);

        // Step 2: Searching for PKCS conforming messages.
        let s_i =
            // Step 2.a: Starting the search.
            if i == 1 {
                range_from(n.div_ceil(&three_b))
                    .find(oracle)
                    .unwrap()
            }
            // Step 2.b: Searching with more than one interval left.
            else if m_prev.len() >= 2 {
                range_from(&s_prev + &one)
                    .find(oracle)
                    .unwrap()
            }
            // Step 2.c: Searching with one interval left.
            else {
                let (a, b) = &m_prev[0];
                let r_start = &two * (b * &s_prev - &two_b).div_ceil(n);

                range_from(r_start)
                    .filter_map(|ref r_i| {
                        let s_start = (&two_b + r_i * n).div_ceil(b);
                        let s_end = (&three_b + r_i * n).div_ceil(a);

                        range(s_start, s_end).find(oracle)
                    })
                    .next()
                    .unwrap()
            };

        println!("s_i = {:?}", s_i);

        // Step 3: Narrowing the set of solutions.
        let mut m_i = m_prev
            .into_iter()
            .flat_map(|(a, b)| {
                let r_start = (&a * &s_i - &three_b + &one).div_ceil(&n);
                let r_end = (&b * &s_i - &two_b).div_floor(&n);

                range_inclusive(r_start, r_end)
                    .map(|ref r| {
                        (
                            max(a.clone(), (&two_b + r * n).div_ceil(&s_i)),
                            min(b.clone(), (&three_b - &one + r * n).div_floor(&s_i)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        m_i.sort();
        m_i.dedup();

        println!("m_i = {:?} ({} {})", m_i, m_i.len(), m_i[0].0 == m_i[0].1);

        // Step 4: Computing the solution.
        if m_i.len() == 1 && m_i[0].0 == m_i[0].1 {
            let m_unpadded =
                <PKCS1v1_5 as EncrytionPadding>::unpad(adversary.pub_key.len_bytes(), &m_i[0].0)
                    .unwrap();

            return m_unpadded;
        }

        s_prev = s_i;
        m_prev = m_i;
    }

    unreachable!()
}

#[test]
#[ignore]
fn crack_256() {
    let cracked_plaintext = crack(256);
    assert!(Adversary::check_solution(&cracked_plaintext));
}

#[test]
#[ignore]
fn crack_768() {
    let cracked_plaintext = crack(768);
    assert!(Adversary::check_solution(&cracked_plaintext));
}
