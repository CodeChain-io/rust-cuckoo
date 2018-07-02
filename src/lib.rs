extern crate byteorder;
extern crate crypto;
extern crate siphasher;

use std::collections::HashMap;
use std::hash::Hasher;

use byteorder::{ByteOrder, NativeEndian};
use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
use siphasher::sip::SipHasher24;

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

        let key = {
            let mut blake_hasher = Blake2b::new(32);
            let mut result = vec![0u8; 32];
            blake_hasher.input(message);
            blake_hasher.result(&mut result);
            let key_0 = NativeEndian::read_u64(&result[0..8]).to_le();
            let key_1 = NativeEndian::read_u64(&result[8..16]).to_le();

            (key_0, key_1)
        };

        let mut from_upper: HashMap<_, Vec<_>> = HashMap::new();
        let mut from_lower: HashMap<_, Vec<_>> = HashMap::new();
        for (u, v) in proof.iter().map(|i| self.edge(key, *i)) {
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

        let mut cycle_length = 1;
        let mut cur_edge = self.edge(key, 0);
        let start = cur_edge.0;
        loop {
            let next_lower = *from_upper[&cur_edge.0].iter().find(|v| **v != cur_edge.1).unwrap();
            let next_upper = *from_lower[&next_lower].iter().find(|u| **u != cur_edge.0).unwrap();

            if start == next_upper {
                break
            }
            cycle_length += 1;
            cur_edge = (next_upper, next_lower);
        }
        cycle_length == self.cycle_length
    }

    pub fn solve(&self, message: Vec<u8>) -> Option<Vec<u32>> {
        unimplemented!()
    }

    fn edge(&self, key: (u64, u64), index: u32) -> (u64, u64) {
        let hasher = SipHasher24::new_with_keys(key.0, key.1);
        let upper = {
            let mut hasher = hasher.clone();
            hasher.write_u32(2 * index + 0);
            hasher.finish() % self.max_vertex as u64
        };
        let lower = {
            let mut hasher = hasher.clone();
            hasher.write_u32(2 * index + 1);
            hasher.finish() % self.max_vertex as u64
        };
        (upper, lower)
    }
}

#[cfg(test)]
mod test {
    use super::Cuckoo;

    #[test]
    fn verify_cuckoo() {
        let cuckoo = Cuckoo::new(16, 8, 6);

        let message = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x01, 0, 0
        ];
        let proof = [0, 1, 2, 3, 4, 5];
        assert!(cuckoo.verify(&message, &proof));

        let message = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbc, 0x03, 0, 0
        ];
        let proof = [1, 3, 4, 5, 6, 7];
        assert!(cuckoo.verify(&message, &proof));
    }
}
