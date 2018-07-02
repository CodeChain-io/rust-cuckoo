extern crate byteorder;
extern crate crypto;

mod sip;

use std::collections::HashMap;

use byteorder::{ByteOrder, NativeEndian};
use crypto::digest::Digest;
use crypto::blake2b::Blake2b;

use sip::CuckooSip;

pub struct Cuckoo {
    max_vertex: usize,
    max_edge: usize,
    cycle_length: usize,
}

impl Cuckoo {
    pub fn new(max_vertex: usize, max_edge: usize, cycle_length: usize) -> Self {
        Self {
            max_vertex,
            max_edge,
            cycle_length,
        }
    }

    pub fn verify(&self, message: &[u8], proof: &[u32]) -> bool {
        if proof.len() != self.cycle_length {
            return false
        }

        // Check if proof values are in valid range
        if proof.iter().any(|i| *i >= self.max_edge as u32) {
            return false
        }

        let keys = {
            let mut blake_hasher = Blake2b::new(32);
            let mut result = vec![0u8; 32];
            blake_hasher.input(message);
            blake_hasher.result(&mut result);

            [
                NativeEndian::read_u64(&result[0..8]).to_le(),
                NativeEndian::read_u64(&result[8..16]).to_le(),
                NativeEndian::read_u64(&result[16..24]).to_le(),
                NativeEndian::read_u64(&result[24..32]).to_le(),
            ]
        };

        let mut from_upper: HashMap<_, Vec<_>> = HashMap::new();
        let mut from_lower: HashMap<_, Vec<_>> = HashMap::new();
        for (u, v) in proof.iter().map(|i| self.edge(&keys, *i)) {
            if !from_upper.contains_key(&u) {
                from_upper.insert(u, Vec::new());
            }
            if !from_lower.contains_key(&v) {
                from_lower.insert(v, Vec::new());
            }
            from_upper.get_mut(&u).unwrap().push(v);
            from_lower.get_mut(&v).unwrap().push(u);
        }
        if from_upper.values().any(|list| list.len() != 2) {
            return false
        }
        if from_lower.values().any(|list| list.len() != 2) {
            return false
        }

        let mut cycle_length = 0;
        let mut cur_edge = self.edge(&keys, 0);
        let start = cur_edge.0;
        loop {
            let next_lower = *from_upper[&cur_edge.0].iter().find(|v| **v != cur_edge.1).unwrap();
            let next_upper = *from_lower[&next_lower].iter().find(|u| **u != cur_edge.0).unwrap();
            cur_edge = (next_upper, next_lower);
            cycle_length += 2;

            if start == cur_edge.0 {
                break
            }
        }
        cycle_length == self.cycle_length
    }

    pub fn solve(&self, message: Vec<u8>) -> Option<Vec<u32>> {
        unimplemented!()
    }

    fn edge(&self, keys: &[u64; 4], index: u32) -> (u64, u64) {
        let hasher = CuckooSip::new(keys[0], keys[1], keys[2], keys[3]);
        let upper = hasher.hash(2 * (index as u64) + 0) % ((self.max_vertex as u64) / 2);
        let lower = hasher.hash(2 * (index as u64) + 1) % ((self.max_vertex as u64) / 2);

        (upper, lower)
    }
}

#[cfg(test)]
mod test {
    use super::Cuckoo;

    #[test]
    fn verify_cuckoo() {
        let testset = [
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1c, 0, 0, 0
                ],
                [0, 1, 2, 4, 5, 6],
            ),
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0
                ],
                [0, 1, 2, 3, 4, 7],
            ),
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf6, 0, 0, 0
                ],
                [0, 1, 2, 4, 5, 7],
            ),
        ];
        let cuckoo = Cuckoo::new(16, 8, 6);
        for (message, proof) in testset.iter() {
            assert!(cuckoo.verify(message, proof));
        }
    }
}
