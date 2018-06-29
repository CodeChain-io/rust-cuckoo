extern crate crypto;

use crypto::digest::Digest;
use crypto::blake2b::Blake2b;

pub fn verify(message: &[u8], proof: &[u32]) -> bool {
    let hash = {
        let mut hasher = Blake2b::new(32);
        let mut result = Vec::new();
        hasher.input(message);
        hasher.result(&mut result);
        result
    };
    unimplemented!()
}

pub fn solve(message: Vec<u8>, length: usize) -> Option<Vec<u32>> {
    unimplemented!()
}
