mod set1;
mod set2;
mod set3;
mod set4;

use rand::{distributions, Rng};

fn gen_random_bytes(length: usize) -> Vec<u8> {
    let rng = rand::thread_rng();

    rng.sample_iter(&distributions::Standard)
        .take(length)
        .collect::<Vec<_>>()
}

fn gen_random_bytes_between(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(min..max);
    gen_random_bytes(length)
}
