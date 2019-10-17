extern crate byteorder;
extern crate crypto;

mod sip;

use std::collections::HashMap;

use byteorder::{ByteOrder, NativeEndian};
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;

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
            from_upper.entry(u).or_default().push(v);
            from_lower.entry(v).or_default().push(u);
        }
        if from_upper.values().any(|list| list.len() != 2) {
            return false
        }
        if from_lower.values().any(|list| list.len() != 2) {
            return false
        }

        let mut cycle_length = 0;
        let mut cur_edge = self.edge(&keys, proof[0]);
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

    pub fn solve(&self, message: &[u8]) -> Option<Vec<u32>> {
        let mut graph = vec![0; self.max_vertex].into_boxed_slice();
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

        for nonce in 0..self.max_edge {
            let (u, v) = {
                let edge = self.edge(&keys, nonce as u32);
                #[allow(clippy::identity_op)]
                (2 * edge.0 + 0, 2 * edge.1 + 1)
            };
            if u == 0 {
                continue
            }
            let path_u = Cuckoo::path(&graph, u);
            let path_v = Cuckoo::path(&graph, v);
            if path_u.last().unwrap() == path_v.last().unwrap() {
                let common = path_u.iter().rev().zip(path_v.iter().rev()).take_while(|(u, v)| u == v).count();
                if (path_u.len() - common) + (path_v.len() - common) + 1 == self.cycle_length {
                    let mut cycle: Vec<_> = {
                        let mut list = Vec::new();
                        list.extend(path_u.iter().take(path_u.len() - common + 1));
                        list.extend(path_v.iter().rev().skip(common));
                        list.push(u);
                        list.windows(2).map(|edge| (edge[0], edge[1])).collect()
                    };
                    let mut result = Vec::new();
                    for n in 0..self.max_edge {
                        let cur_edge = {
                            let edge = self.edge(&keys, n as u32);
                            #[allow(clippy::identity_op)]
                            (2 * edge.0 + 0, 2 * edge.1 + 1)
                        };
                        for i in 0..cycle.len() {
                            let cycle_edge = cycle[i];
                            if cycle_edge == cur_edge || (cycle_edge.1, cycle_edge.0) == cur_edge {
                                result.push(n as u32);
                                cycle.remove(i);
                                break
                            }
                        }
                    }
                    return Some(result)
                }
            } else if path_u.len() < path_v.len() {
                for edge in path_u.windows(2) {
                    graph[edge[1] as usize] = edge[0];
                }
                graph[u as usize] = v;
            } else {
                for edge in path_v.windows(2) {
                    graph[edge[1] as usize] = edge[0];
                }
                graph[v as usize] = u;
            }
        }
        None
    }

    fn path(graph: &[u64], start: u64) -> Vec<u64> {
        let mut node = start;
        let mut path = vec![start];
        loop {
            node = graph[node as usize];
            if node != 0 {
                path.push(node);
            } else {
                break
            }
        }
        path
    }

    fn edge(&self, keys: &[u64; 4], index: u32) -> (u64, u64) {
        let hasher = CuckooSip::new(keys[0], keys[1], keys[2], keys[3]);
        #[allow(clippy::identity_op)]
        let upper = hasher.hash(2 * (index as u64) + 0) % ((self.max_vertex as u64) / 2);
        let lower = hasher.hash(2 * (index as u64) + 1) % ((self.max_vertex as u64) / 2);

        (upper, lower)
    }
}

#[cfg(test)]
mod test {
    use super::Cuckoo;

    const TESTSET: [([u8; 80], [u32; 6]); 3] = [
        (
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0x1c, 0, 0, 0,
            ],
            [0, 1, 2, 4, 5, 6],
        ),
        (
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0,
            ],
            [0, 1, 2, 3, 4, 7],
        ),
        (
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0xf6, 0, 0, 0,
            ],
            [0, 1, 2, 4, 5, 7],
        ),
    ];

    #[test]
    fn solve_cuckoo() {
        let cuckoo = Cuckoo::new(16, 8, 6);
        for (message, proof) in TESTSET.iter() {
            assert_eq!(cuckoo.solve(message).unwrap(), proof);
        }
    }

    #[test]
    fn verify_cuckoo() {
        let cuckoo = Cuckoo::new(16, 8, 6);
        for (message, proof) in TESTSET.iter() {
            assert!(cuckoo.verify(message, proof));
        }
    }
}
