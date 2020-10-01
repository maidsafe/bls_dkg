// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
};
use xor_name::XorName;

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: XorName,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl PeerId {
    pub fn new() -> Self {
        let (public_key, secret_key) = gen_keypair();
        let mut rng = rand::thread_rng();
        Self {
            id: rng.gen(),
            public_key,
            secret_key,
        }
    }

    pub fn name(&self) -> XorName {
        self.id
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.public_key.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.public_key == other.public_key
    }
}

impl Eq for PeerId {}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &PeerId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &PeerId) -> Ordering {
        self.id.cmp(&other.id)
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    let mut ids: Vec<PeerId> = (0..count).map(|_| PeerId::new()).collect();
    ids.sort();
    ids
}

const SIGNATURE_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;

// **NOT FOR PRODUCTION USE**: Mock public key.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PublicKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock signature.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Signature(..)")
    }
}

fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut rng = rand::thread_rng();
    let bytes: [u8; KEY_LENGTH] = rng.gen();
    (PublicKey(bytes), SecretKey(bytes))
}
