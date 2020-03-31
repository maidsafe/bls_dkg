// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::SeededRng;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fmt;

pub trait RngDebug: Rng + fmt::Debug {}

impl RngDebug for SeededRng {}
impl RngDebug for XorShiftRng {}

#[derive(Clone, Copy, Debug)]
pub enum RngChoice {
    SeededRandom,
    #[allow(unused)]
    Seeded([u32; 4]),
    SeededXor([u32; 4]),
}

/// Create a new Rng: Use once per test.
pub fn new_common_rng(seed: RngChoice) -> Box<dyn RngDebug> {
    match seed {
        RngChoice::SeededRandom => Box::new(SeededRng::new()),
        RngChoice::Seeded(seed) => Box::new(SeededRng::from_seed(seed)),
        RngChoice::SeededXor(seed) => {
            let rng = Box::new(XorShiftRng::from_seed(seed));
            println!("Using {:?}", rng);
            rng
        }
    }
}

/// Create a new RNG using a seed generated from random data provided by `rng`.
pub fn new_rng<R: Rng>(rng: &mut R) -> Box<dyn Rng> {
    let new_seed = [
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
    ];
    Box::new(XorShiftRng::from_seed(new_seed))
}

/// Create a RNG that will replay the given value and when complete will panic if more value needed.
pub struct ReplayRng {
    values: Vec<u32>,
    index: usize,
}

impl ReplayRng {
    /// Create ReplayRng that will replay the given `values`.
    pub fn new(values: Vec<u32>) -> Self {
        Self { values, index: 0 }
    }
}

impl Rng for ReplayRng {
    fn next_u32(&mut self) -> u32 {
        let value = unwrap!(self.values.get(self.index));
        self.index += 1;
        *value
    }
}
