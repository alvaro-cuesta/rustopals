//! Solutions for [Matasano Crypto Challenges](https://cryptopals.com/) implemented
//! in [Rust](https://www.rust-lang.org/).
//!
//! The final product should be a library of cryptographic primitives, implementing
//! as much crypto as possible (instead of using libraries). Code should be as
//! generic as possible. Usage of traits and generics instead of concrete types is
//! encouraged.
//!
//! The challenges will serve only as integration tests cases: the actual library
//! code is not organized around sets. If you want to review a specific challenge,
//! find it under the `/tests/` folder and explore the used functions.
//!
//! This is **not** a crypto library _(don't roll your own crypto!)_ but it should
//! serve as a real-world exercise.

#![feature(step_trait)]
#![feature(test)]

#[cfg(test)]
extern crate test;

pub mod block;
pub mod digest;
pub mod mac;
pub mod rand;
pub mod stream;
pub mod util;
